#!/usr/bin/env python3
"""Synthetic file/identity/stopping controls; no native experiment claims."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run_sp27_strata_controls as strata


class SyntheticCampaignControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.out = Path(self.temporary.name).resolve()
        (self.out / 'native/raw').mkdir(parents=True)
        (self.out / 'native/inputs').mkdir()
        binary = self.out / 'synthetic-never-executed'
        binary.write_bytes(b'synthetic data only, not an executable')
        files = {strata.native.SOURCE: 'b' * 64, strata.MODULE: 'c' * 64,
                 strata.STRATA_MODULE: 'd' * 64, strata.CAMPAIGN_MODULE: 'e' * 64}
        self.prepared = {'source_before': {'commit': 'a' * 40, 'files_sha256': files},
            'binary': strata.history.file_observation(binary, 1024)[0],
            'job': {'GITHUB_JOB': 'synthetic', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_ID': '123'}}
        self.identity = {'schema': 'sp27-receiver-run-identity-v1', 'pid': 1234,
            'hostname': 'synthetic', 'boot_id': 'synthetic-boot',
            'process_cgroup': '0::/trnmponpublic.slice/synthetic.service',
            'binary_identity_error': None, 'binary_path': str(binary), 'binary_sha256': strata.digest(binary),
            'runner_declared_source_sha': 'a' * 40, 'runner_declared_run_id': '123-1-synthetic',
            'github_run_id': '123', 'github_run_attempt': '1',
            'compiled_test_source_sha256': files[strata.native.SOURCE],
            'compiled_health_module_sha256': files[strata.MODULE],
            'compiled_strata_module_sha256': files[strata.STRATA_MODULE],
            'compiled_campaign_module_sha256': files[strata.CAMPAIGN_MODULE]}
        self.host = {'schema': 'sp27-receiver-host-readback-v1',
            'fixed_parent': '/sys/fs/cgroup/trnmponpublic.slice', 'verified': True,
            'sample': {'synthetic_fixture_only': True}, 'error': None}
        for when in ('before', 'after'):
            self.save(f'identity-{when}.json', self.identity)
            self.save(f'host-{when}.json', self.host)
        self.plan = strata.planned_phases()
        self.save('plan.json', {'schema': 'sp27-receiver-strata-campaign-plan-v1',
            'planned_phases': self.plan, 'initial_health_repetitions': 3, 'control_phase_count': 8,
            'sentinel_count': 2, 'arm_names': list(strata.ARMS), 'balanced_arm_indices': list(strata.ORDER),
            'same_seven_signed_packets': True, 'confirmation_depth': 6,
            'requested_window_ns': strata.WINDOW_NS, 'pressure_workers_max': 16,
            'pressure_per_worker_attempt_cap': 1, 'control_scheduled_arrival_ns': 100_000_000,
            'global_per_worker_attempt_ceiling': 1024, 'outer_selector_timeout_seconds': 90,
            'fixed_parent': '/sys/fs/cgroup/trnmponpublic.slice',
            'required_cpu_quota_us': 25000, 'required_cpu_period_us': 100000,
            'required_memory_bytes': 2147483648, 'required_swap_bytes': 0})
        self.save('business-acquisition-started.json', {'kind': 'synthetic-business'})
        self.save('business-acquisition.json', {'schema': 'sp27-receiver-seven-packet-acquisition-v1',
            'same_seven_packets_in_all_health_phases': True,
            'signed_honest_packets': [f'{i:04x}' for i in range(7)],
            'packet_ids': [f'{i:064x}' for i in range(7)]})
        # These short packet strings deliberately are not valid proofs. The
        # reader binds recorded bytes; this unit suite does no native replay.
        self.requests = [[f'{arm:02x}{i:02x}' for i in range(16)] for arm in range(4)]
        self.save_inputs()
        self.records, self.raw = [], []
        for index, plan in enumerate(self.plan):
            self.records.append({**plan, 'attempted': True, 'helper_invoked': True,
                                 'completed': True, 'host_before_verified': True,
                                 'host_after_verified': True, 'stopped_campaign': False})
            phase = self.health_phase() if plan['arm'] is None else self.pressure_phase(plan['arm'])
            self.raw.append(phase)
            self.save_phase(index)
        self.report = {'schema': 'sp27-receiver-strata-campaign-v1',
            'qualification': 'COLLECTED_CONTROL_SERIES', 'planned_phases': 13,
            'planned_health_repetitions': 3, 'planned_sentinels': 2,
            'pressure_controls_planned': 8, 'balanced_arm_indices': list(strata.ORDER),
            'requested_window_ns': strata.WINDOW_NS, 'mechanism_status': 'UNKNOWN',
            'causal_mechanism_status': 'UNKNOWN', 'publication_qualified': False,
            'public_network_ready': False, 'production_activation': False,
            'binary_unchanged': True, 'host_before_verified': True, 'host_after_verified': True,
            'control_inputs_acquired': True, 'first_divergence': None}
        self.refresh()

    def save(self, name, value):
        path = self.out / 'native' / name
        path.write_text(json.dumps(value, sort_keys=True) + '\n')
        return strata.digest(path)

    @staticmethod
    def request_identity(wire):
        body = json.dumps({'op': 'submit', 'packet': wire}, separators=(',', ':')).encode()
        return {'packet_hex': wire, 'request_bytes': len(body),
                'body_digest': strata.native.H('public-request-body-v3', body).hex(),
                'recorded_request_digest': strata.native.H('pressure-recorded-request-v1', body).hex()}

    def save_inputs(self):
        self.save('strata-acquisition-started.json', {'kind': 'synthetic-inputs'})
        identities = [[self.request_identity(wire) for wire in wires] for wires in self.requests]
        inputs = []
        for index, arm in enumerate(strata.ARMS):
            name = f'inputs/arm-{index:03}.json'
            digest = self.save(name, {'schema': 'sp27-receiver-control-request-stream-v1',
                'arm_index': index, 'arm': arm, 'request_count': 16, 'requests': self.requests[index],
                'packet_hex_bytes': sum(map(len, self.requests[index])),
                'canonical_submit_body_bytes': [v['request_bytes'] for v in identities[index]]})
            inputs.append({'arm_index': index, 'arm': arm, 'request_count': 16,
                           'raw_record': name, 'sha256': digest})
        self.save('strata-inputs-index.json', {'schema': 'sp27-receiver-control-input-index-v1',
                  'same_request_streams_for_balanced_repeats': True, 'inputs': inputs})
        self.save('strata-input-acquisition-native.json', {'schema': 'sp27-strata-input-acquisition-v1',
            'arms': list(strata.ARMS), 'workers_per_arm': 16, 'calls_per_worker': 1,
            'valid_expensive_is_not_a_pure_W1_intervention': True, 'inputs': identities,
            'canonical_submit_body_bytes_each': identities[0][0]['request_bytes']})

    @staticmethod
    def health_phase():
        return {'workers': 0, 'requested_window_ns': strata.WINDOW_NS,
            'invariant_target_met': True, 'finite_business_target_met': True,
            'client_confirmed_before_original_window_end': True,
            'client_confirmed_transactions': 1, 'confirmation_ended_ns': strata.WINDOW_NS - 1,
            'full_native_state_equal': True, 'verification_errors': []}

    def pressure_phase(self, arm):
        valid, late = arm == 'valid-expensive', arm == 'late-reject'
        full = valid or late
        names = ['body_decode', 'decode', 'context', 'work', 'submit_result']
        outcome = ([True, False, None, None, None] if arm == 'transport' else
                   [True, True, False, None, None] if arm == 'early-reject' else
                   [True, True, True, False, None] if late else [True] * 5)
        stages = [{'phase': name, 'started': result is not None, 'completed': result is not None,
                   'accepted': result, 'error_code': 'HEADER_CODEC' if name == 'decode' and arm == 'transport'
                   else None} for name, result in zip(names, outcome)]
        wire = self.requests[strata.ARMS.index(arm)][0]
        body_digest = self.request_identity(wire)['body_digest']
        rejection = {'schema': 'public-v3-work-rejection-observation-v1', 'completed': True,
            'cache': {'native_verifier_started': True, 'native_verifier_returned': True,
                      'full_replay_started': True, 'cached_rejection_returned': False}} if full else None
        record = {'connection_id': 1, 'body_digest': list(bytes.fromhex(body_digest)),
            'full_work_started': full, 'full_work_accepted': valid if full else None,
            'dispatch_accepted': valid, 'work_rejection': rejection, 'submit_phases': stages,
            'error_diagnostics': {'dispatch': {'message_prefix': 'WORK:Transcript' if late else 'WORK:Task',
                                             'message_truncated': False}},
            'lifecycle': None, 'paid_task_queue_wait': None, 'terminal_phase': None,
            'terminal_error_code': None, 'complete': True, 'observation_failed': False}
        witness = {'packet_index': 0, 'connection_id': 1, 'body_digest': body_digest,
            'actual_body_checked': True, 'target_stage_attained': True, 'full_native_replay_observed': full,
            **{key: record[key] for key in ('dispatch_accepted', 'lifecycle', 'paid_task_queue_wait',
                                          'work_rejection', 'submit_phases', 'terminal_phase', 'terminal_error_code')}}
        return {'schema': 'sp27-native-stage-control-phase-v1', 'mode': arm,
            'workers': 16, 'requested_window_ns': strata.WINDOW_NS,
            'client_confirmed_before_original_window_end': False,
            'client_confirmed_transactions': 0, 'confirmation_ended_ns': None,
            'full_native_state_equal': False, 'verification_errors': ['synthetic deadline'],
            'finite_business_target_met': False, 'invariant_target_met': True,
            'control_integrity_met': True, 'accounting_closed': True,
            'receiver_matches_valid_honest_prefix': True, 'no_attack_accepted': not valid,
            'arrival_plan': {'workers': 16, 'attempts_per_worker': 1, 'scheduled_start_ns': 100_000_000,
                             'retries': 0, 'business_waits_for_pressure_completion': False},
            'attacks': [{'worker': i, 'planned_attempts': 1, 'calls': [{
                'packet_index': i, 'attempt_index': 0, 'scheduled_start_ns': 100_000_000,
                'offering_thread_ready_ns': 100_000_100, 'offering_lateness_ns': 100,
                'started_ns': 100_000_200,
                'status': ('ok' if valid else 'refused') if i == 0 else 'error'}]} for i in range(16)],
            'observations': {'records_not_retained': 0, 'measurement_failures': 0,
                'counter_overflow': False, 'accepted_connections_seen': 1, 'records': [record]},
            'service': {'error': None, 'metrics': {'mutation_cpu_charged_ns': 10,
                'mutation_full_work_cpu_ns': 7, 'mutation_dispatch_excluding_work_cpu_ns': 3,
                'work_started': int(full), 'work_finished': int(full), 'mutation_cpu_clock_failures': 0}},
            'stage_readback': {'schema': 'sp27-native-stage-readback-v1', 'arm': arm,
                'planned_offerings': 16, 'actual_calls_started': 16,
                'matched_claimed_body_connections': 1, 'target_stage_attained': 1,
                'input_stage_identifiable': True, 'unexpected_stage_or_acceptance': False,
                'matched_records': [witness]}}

    def save_phase(self, index):
        row, phase = self.records[index], self.raw[index]
        plan = self.plan[index]
        prefix = 'raw/' + plan['phase_id']
        self.save(prefix + '-started.json', {'schema': 'sp27-receiver-campaign-phase-started-v1',
            'status': 'STARTED_NOT_YET_OBSERVED_COMPLETE', 'plan': {**plan, 'attempted': True,
            'helper_invoked': False, 'completed': False, 'raw_phase_record': None, 'raw_phase_sha256': None}})
        self.save(prefix + '-invoked.json', {'schema': 'sp27-receiver-campaign-phase-invoked-v1',
            'phase_id': plan['phase_id'], 'planned_index': index,
            'requested_window_ns': strata.WINDOW_NS, 'helper_invoked': True})
        for when in ('before', 'after'):
            self.save(prefix + '-host-' + when + '.json', self.host)
        row.update(raw_phase_record=prefix + '.json', raw_phase_sha256=self.save(prefix + '.json', phase),
                   business_result_is_not_campaign_integrity=plan['arm'] is not None,
                   native_final_gate=phase['client_confirmed_before_original_window_end'])
        row.update({key: phase.get(key) for key in ('confirmation_ended_ns', 'client_confirmed_transactions',
                   'control_integrity_met', 'invariant_target_met', 'finite_business_target_met')})
        if plan['arm'] is None:
            row['healthy'] = phase['client_confirmed_before_original_window_end']
        self.save(prefix + '-index.json', row)

    def refresh(self):
        health = [r for r in self.records if r['arm'] is None]
        controls = [r for r in self.records if r['arm'] is not None]
        completed = sum(r['completed'] for r in self.records)
        self.report.update(phases=self.records, health_phases=health, control_phases=controls,
            attempted_phases=len(self.records), completed_phases=completed,
            helper_invoked_phases=sum(r['helper_invoked'] for r in self.records),
            incomplete_phases=len(self.records) - completed, unstarted_phases=13 - len(self.records),
            health_gate_passed=len(self.records) >= 3 and all(r.get('healthy') is True
                and not r['stopped_campaign'] for r in self.records[:3]),
            healthy_completed_phases=sum(r.get('healthy') is True for r in health),
            pressure_controls_attempted=len(controls),
            pressure_controls_executed=sum(r['completed'] for r in controls),
            pressure_controls_unstarted=8 - len(controls))
        self.save('report.json', self.report)

    def stop_at_unhealthy(self, index, *, continue_one=False):
        self.raw[index].update(client_confirmed_before_original_window_end=False,
                               client_confirmed_transactions=0)
        self.records[index]['stopped_campaign'] = True
        self.save_phase(index)
        keep = index + 2 if continue_one else index + 1
        for plan in self.plan[keep:]:
            for path in (self.out / 'native/raw').glob(plan['phase_id'] + '*.json'):
                path.unlink()
        self.records = self.records[:keep]
        if index < 3:
            self.report['control_inputs_acquired'] = False
            for name in ('strata-acquisition-started.json', 'strata-inputs-index.json',
                         'strata-input-acquisition-native.json'):
                (self.out / 'native' / name).unlink()
            for path in (self.out / 'native/inputs').glob('*.json'):
                path.unlink()
        failure = {'schema': 'sp27-receiver-campaign-first-divergence-v1', 'qualification': 'NO_GO',
            'stage': 'unhealthy-sentinel', 'planned_index': index,
            'phase_id': self.plan[index]['phase_id'], 'causal_status': 'UNKNOWN'}
        self.report.update(qualification='NO_GO', first_divergence=failure)
        self.save('first-divergence.json', failure)
        self.refresh()

    def read(self):
        return strata.read_campaign(self.out, self.prepared)

    def test_complete_series_allows_pressure_nonconfirmation_and_valid_acceptance(self):
        report, _, files = self.read()
        self.assertEqual(report['qualification'], 'COLLECTED_CONTROL_SERIES')
        self.assertEqual(report['completed_phases'], 13)
        self.assertEqual(report['healthy_completed_phases'], 5)
        self.assertTrue(all(r['native_final_gate'] is False for r in report['control_phases']))
        self.assertIn('raw/control-003-valid-expensive.json', files)

    def test_plan_is_three_health_then_two_reversed_blocks_and_sentinels(self):
        self.assertEqual([p['arm'] for p in self.plan], [None, None, None, 'transport', 'early-reject',
            'late-reject', 'valid-expensive', None, 'valid-expensive', 'late-reject', 'early-reject',
            'transport', None])
        self.assertEqual(strata.NATIVE_TIMEOUT_SECONDS, 90)

    def test_first_health_failure_preserves_denominators_and_stops(self):
        self.stop_at_unhealthy(0)
        report, _, _ = self.read()
        self.assertEqual((report['completed_phases'], report['unstarted_phases']), (1, 12))
        self.assertEqual(report['pressure_controls_attempted'], 0)

    def test_midpoint_failure_stops_reverse_block(self):
        self.stop_at_unhealthy(7)
        report, _, _ = self.read()
        self.assertEqual((report['pressure_controls_executed'], report['pressure_controls_unstarted']), (4, 4))

    def stop_incomplete(self, *, invoked):
        index = 3
        row = self.records[index]
        prefix = 'raw/' + row['phase_id']
        for key in ('native_final_gate', 'confirmation_ended_ns', 'client_confirmed_transactions',
                    'control_integrity_met', 'invariant_target_met', 'finite_business_target_met',
                    'business_result_is_not_campaign_integrity'):
            row.pop(key, None)
        row.update(helper_invoked=invoked, completed=False, raw_phase_record=None,
                   raw_phase_sha256=None, stopped_campaign=True, host_before_verified=invoked)
        (self.out / 'native' / (prefix + '.json')).unlink()
        if invoked:
            row['panic_record'] = prefix + '-panic.json'
            self.save(row['panic_record'], {'schema': 'sp27-receiver-campaign-native-panic-v1',
                'phase_id': row['phase_id'], 'planned_index': index,
                'raw_phase_complete': False, 'native_confirmation_result': None,
                'panic': 'synthetic panic only'})
        else:
            (self.out / 'native' / (prefix + '-invoked.json')).unlink()
            self.save(prefix + '-host-before.json', dict(self.host, verified=False,
                                                       sample=None, error='PUBLIC_HOST_KERNEL_PARENT'))
        self.save(prefix + '-index.json', row)
        for plan in self.plan[index + 1:]:
            for path in (self.out / 'native/raw').glob(plan['phase_id'] + '*.json'):
                path.unlink()
        self.records = self.records[:index + 1]
        failure = {'schema': 'sp27-receiver-campaign-first-divergence-v1', 'qualification': 'NO_GO',
            'stage': 'native-phase-panic' if invoked else 'phase-pre-host', 'planned_index': index,
            'phase_id': row['phase_id'], 'causal_status': 'UNKNOWN'}
        self.report.update(qualification='NO_GO', first_divergence=failure)
        self.save('first-divergence.json', failure)
        self.refresh()

    def test_pre_host_failure_counts_attempt_but_never_helper_invocation(self):
        self.stop_incomplete(invoked=False)
        report, _, _ = self.read()
        self.assertEqual([report[key] for key in ('attempted_phases', 'helper_invoked_phases',
                          'completed_phases', 'incomplete_phases', 'unstarted_phases')], [4, 3, 3, 1, 9])
        self.assertEqual(report['pressure_controls_executed'], 0)

    def test_native_panic_retains_invoked_incomplete_phase_and_original_panic(self):
        self.stop_incomplete(invoked=True)
        report, _, files = self.read()
        self.assertEqual([report[key] for key in ('attempted_phases', 'helper_invoked_phases',
                          'completed_phases', 'incomplete_phases', 'unstarted_phases')], [4, 4, 3, 1, 9])
        self.assertIn('raw/control-000-transport-panic.json', files)

    def test_missing_native_panic_record_is_not_successful_incomplete_collection(self):
        self.stop_incomplete(invoked=True)
        (self.out / 'native/raw/control-000-transport-panic.json').unlink()
        with self.assertRaises(OSError):
            self.read()

    def test_post_failure_attempt_cannot_hide_behind_completed_counts(self):
        self.stop_at_unhealthy(7, continue_one=True)
        with self.assertRaisesRegex(ValueError, 'SP27_STRATA_CONTINUED_AFTER_STOP'):
            self.read()

    def test_unindexed_future_started_record_is_rejected(self):
        self.stop_at_unhealthy(0)
        self.save('raw/control-000-transport-started.json', {'hidden_future_attempt': True})
        with self.assertRaisesRegex(ValueError, 'SP27_STRATA_UNINDEXED_OR_MISSING_RAW'):
            self.read()

    def test_compiled_modules_and_declared_run_are_bound_to_preparation(self):
        for key in ('compiled_test_source_sha256', 'compiled_health_module_sha256',
                    'compiled_strata_module_sha256', 'compiled_campaign_module_sha256',
                    'binary_sha256', 'runner_declared_source_sha', 'runner_declared_run_id'):
            changed = dict(self.identity, **{key: 'changed'})
            for when in ('before', 'after'):
                self.save(f'identity-{when}.json', changed)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'SP27_STRATA_BUILD_RUN_BINDING'):
                self.read()

    def test_numeric_report_types_cannot_coerce_boolean_or_float(self):
        for key, value in (('planned_phases', 13.0), ('attempted_phases', 13.0),
                           ('incomplete_phases', False), ('unstarted_phases', False)):
            self.refresh()
            self.save('report.json', dict(self.report, **{key: value}))
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.read()

    def test_raw_digest_and_phase_index_are_checked_separately(self):
        name = self.records[0]['raw_phase_record']
        self.save(name, dict(self.raw[0], workers=False))
        with self.assertRaisesRegex(ValueError, 'SP27_STRATA_RAW_CHANGED'):
            self.read()

    def test_native_true_gate_at_exact_deadline_is_rejected_after_rehash(self):
        self.raw[0]['confirmation_ended_ns'] = strata.WINDOW_NS
        self.save_phase(0)
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'SP27_STRATA_NATIVE_FINAL_GATE_CONTRADICTION'):
            self.read()

    def test_false_gate_before_deadline_is_not_promoted_to_confirmation(self):
        self.raw[3]['confirmation_ended_ns'] = strata.WINDOW_NS - 1
        self.save_phase(3)
        self.refresh()
        self.assertIs(self.read()[0]['control_phases'][0]['native_final_gate'], False)

    def test_pressure_workers_boolean_or_different_cap_are_rejected(self):
        for value in (True, 1, 17):
            self.raw[3]['workers'] = value
            self.save_phase(3)
            self.refresh()
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'SP27_STRATA_PRESSURE_SCOPE'):
                self.read()

    def test_claimed_stage_witness_cannot_replace_original_observer(self):
        self.raw[5]['observations']['records'][0]['work_rejection']['cache']['full_replay_started'] = False
        self.save_phase(5)
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'SP27_STRATA_STAGE_WITNESS_CHANGED'):
            self.read()

    def test_malformed_observer_row_is_a_recorded_validation_refusal(self):
        self.raw[3]['observations']['records'][0] = None
        self.save_phase(3)
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'SP27_STRATA_OBSERVATIONS_REQUIRED'):
            self.read()

    def test_changed_input_stream_is_not_accepted_by_unmodified_sha_index(self):
        path = self.out / 'native/inputs/arm-000.json'
        value = json.loads(path.read_text())
        value['requests'][0] = 'ffff'
        self.save('inputs/arm-000.json', value)
        with self.assertRaisesRegex(ValueError, 'SP27_STRATA_INPUT_SHA'):
            self.read()

    def test_missing_phase_host_or_invocation_file_is_rejected(self):
        for suffix in ('-host-before.json', '-host-after.json', '-invoked.json'):
            path = self.out / ('native/raw/health-000' + suffix)
            raw = path.read_bytes()
            path.unlink()
            try:
                with self.subTest(suffix=suffix), self.assertRaises(OSError):
                    self.read()
            finally:
                path.write_bytes(raw)

    def test_readback_file_replacement_is_rejected_at_execution_binding(self):
        report, observed, readback = self.read()
        manifest = {'schema': strata.SCHEMA, 'collection_completed': True, 'failures': [],
            'job': self.prepared['job'], 'causal_mechanism_established': False,
            'runtime_limits_or_deadlines_changed': False,
            'source_before': self.prepared['source_before'], 'source_after': self.prepared['source_before'],
            'binary_before': self.prepared['binary'], 'binary_after': self.prepared['binary'],
            'report_file': observed, 'qualification': report['qualification'], 'native_readback_files': readback}
        (self.out / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True))
        self.save('identity-after.json', self.identity)
        with patch.object(strata, 'validate_preparation', return_value=self.prepared), \
                patch.object(strata.history, 'job_identity', return_value=self.prepared['job']), \
                self.assertRaisesRegex(ValueError, 'SP27_NATIVE_READBACK_CHANGED'):
            strata.bind_execution(self.prepared, self.out)


if __name__ == '__main__':
    unittest.main()
