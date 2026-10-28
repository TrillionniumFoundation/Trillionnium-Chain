#!/usr/bin/env python3
"""Reader counterexamples only; these synthetic records are not native evidence."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_public_v3_phase_read as reader
from test_pon_public_v3_policy_read import arithmetic_observation as arithmetic_policy, observation


def record():
    return {'complete': True, 'observation_failed': False, 'dispatch_started': True,
            'dispatch_accepted': False, 'dispatch_thread_cpu_ns': 100,
            'full_work_started': True, 'full_work_accepted': False, 'full_work_thread_cpu_ns': 30,
            'submit_phases': [{'phase': phase, 'started': False, 'completed': False,
                               'accepted': None, 'wall_ns': None, 'thread_cpu_ns': None}
                              for phase in reader.PHASES]}


def attribution_phase(submissions, history, attacks, records):
    """Only role-matching fields vary; this is not a measured native campaign."""
    return {
        'mode': 'baseline', 'state_backend': 'authenticated-v1', 'duration_seconds': 30,
        'confirmations': [], 'all_signed_rounds_confirmed_in_window': False,
        'finite_phase_criteria_met': False,
        'submissions': submissions, 'history': history,
        'children': [{'report': {'result': {'calls': attacks}}}],
        'receiver_observation': {
            'schema': 'public-v3-local-request-resource-observation-v2',
            'cpu_intervals_are_nested_not_additive': True,
            'submit_phase_cpu_excludes_scoped_workers': True, 'records': records,
        },
        'observer_complete': True, 'service_outcome': {}, 'final_meter': {},
        'verifier_errors': [], 'receiver_client_state_equal': False,
        'genuine_budget_depletion_observed': False,
        'attacker_processes_requested': 0, 'attacker_processes_ready': 0,
        'actor_reports_successful_without_cap_or_kill': False,
        'whole_parent_phase_cpu_ns': None, 'whole_parent_phase_wall_ns': None,
        'receiver_and_verifier_setup_cpu_ns': None,
        'receiver_and_verifier_setup_wall_ns': None,
    }


def completion_observation():
    return dict(schema='public-v3-live-owner-completion-work-v1',
        identity_domain='public-v3-complete-work-identity-v1', identity_capacity=4096,
        identity_storage_bytes=131072, retained_identities=2, live_completions=0,
        repeated_identity_skips=1, full_capacity_skips=0,
        epoch_scope='same-shared-live-cpu-owner', evicts_live_epoch_identities=False,
        survives_process_restart=False, full_capacity_disables_ordinary_verification=False)


def attribution_call(body_digest):
    return {'status': 'refused', 'returned_after_window': False,
            'public_request_body_digest': body_digest,
            'response': {'value': {'error': 'SYNTHETIC_CONTROL'}}, 'error': None}


def arithmetic_work(reused=False, completed=True):
    return dict(schema='public-v3-work-arithmetic-observation-v1', slots=64,
        retained_software_bytes=4000000, completed=completed,
        arithmetic=(dict(lookup_probes=1 if reused else 64, lookup_contended=False,
            exact_fact_found=reused, trace_reused=reused, product_reused=reused,
            transcript_entered=not reused, transcript_completed=not reused,
            product_entered=not reused, product_completed=not reused,
            publication_probes=0 if reused else 64,
            publication='none' if reused else 'product') if completed else None))


def arithmetic_report():
    """Exact native producer shape, with synthetic unknown/failed measurements."""
    phases = [attribution_phase([], [], [], [
        {**record(), 'work_arithmetic': arithmetic_work()},
        {**record(), 'work_arithmetic': arithmetic_work(reused=True)},
        {**record(), 'work_arithmetic': arithmetic_work(completed=False)}, record()])
        for _ in reader.MODES]
    for phase, mode in zip(phases, reader.MODES):
        phase.update(mode=mode, public_resource_policy=arithmetic_policy(),
            work_profile='arithmetic-facts-v1', completion_work_observation=completion_observation(),
            work_arithmetic_owner=dict(schema='public-v3-campaign-arithmetic-owner-v1',
                initial_state='fresh-empty-by-construction', slots=64,
                retained_software_bytes=4000000, setup_cpu_ns=1, setup_wall_ns=2,
                scope='synthetic producer-shaped control; retained software, not RSS',
                adversarial_key_churn_service_qualified=False))
        phase['receiver_observation'].update(schema='public-v3-local-request-resource-observation-v3',
            cpu_includes_reactor_authentication_or_response_signing=True,
            cpu_includes_reactor_authentication=False,
            dispatch_cpu_includes_paid_body_decode=True, dispatch_cpu_includes_response_signing=True)
    return dict(schema=reader.ARITHMETIC_REPORT_SCHEMA,
        state_backend='authenticated-v1', work_profile='arithmetic-facts-v1',
        original_r13_campaign_qualified=False, adversarial_key_churn_service_qualified=False,
        public_resource_policy=arithmetic_policy(), finite_experiment_criteria_met=False,
        economics_complete=False, best_observed_cold_legal_method=None,
        preparation=dict(cpu_ns=None, wall_ns=None), phases=phases)


class ReaderTests(unittest.TestCase):
    def test_r14_policy_preserves_failures_and_cannot_relabel_r13_phases(self):
        report = arithmetic_report()
        report['public_resource_policy'] = arithmetic_policy('r14')
        with self.assertRaisesRegex(ValueError, 'mixed or missing phase resource policies'):
            reader.analyze(report)
        for phase in report['phases']:
            phase['public_resource_policy'] = arithmetic_policy('r14')
        result = reader.analyze(report)
        self.assertEqual(result['public_resource_policy']['resource_revision'],
                         'r14-arithmetic-facts-v1')
        self.assertEqual([p['confirmed_rounds'] for p in result['phases']], [0, 0, 0])
        self.assertFalse(result['native_finite_experiment_criteria_met'])
        self.assertFalse(result['scope']['original_r13_campaign_qualified'])
        for phase in report['phases']:
            phase['public_resource_policy'] = observation('r14')
            del phase['work_profile']
            del phase['work_arithmetic_owner']
            for row in phase['receiver_observation']['records']:
                row.pop('work_arithmetic', None)
        report['schema'] = 'native-public-v3-separate-process-campaign-v2'
        report['public_resource_policy'] = observation('r14')
        del report['work_profile']
        raw_result = reader.analyze(report)
        self.assertEqual([p['public_resource_policy']['resource_revision']
                          for p in raw_result['phases']], ['r14'] * 3)
        self.assertEqual([p['confirmed_rounds'] for p in raw_result['phases']], [0, 0, 0])
        del report['phases'][0]['completion_work_observation']
        with self.assertRaisesRegex(ValueError, 'completion-work observation'):
            reader.analyze(report)

    def test_original_native_raw_report_remains_historical_and_cannot_claim_arithmetic(self):
        path = Path(__file__).resolve().parents[2] / 'evidence/pon-upgrade-implementation-20261018/native-rounds/chain-390-operational/public-v3-multiprocess/report.json'
        original = 'c662cf7d71adec835eb22e60058e3eccb7dc3faa88a31e262ec1bd4bdc069233'
        value = reader.read_report(path, original)
        self.assertNotIn('work_profile', value)
        self.assertNotIn('public_resource_policy', value)
        self.assertNotIn('work_arithmetic', value['phases'][0]['receiver']['all_retained_records'])
        self.assertFalse(value['native_finite_experiment_criteria_met'])
        self.assertEqual([phase['confirmed_rounds'] for phase in value['phases']], [0, 0, 0])
        self.assertTrue(all(phase['genuine_budget_depletion_observed'] for phase in value['phases']))
        with self.assertRaisesRegex(ValueError, 'absent from historical'):
            reader.read_report(path, original, arithmetic_policy()['policy_id'])
        report = json.loads(path.read_bytes())
        report.update(schema=reader.ARITHMETIC_REPORT_SCHEMA, work_profile='arithmetic-facts-v1')
        with self.assertRaisesRegex(ValueError, 'requires explicit policy'):
            reader.analyze(report)

    def test_arithmetic_report_recomputes_identity_and_preserves_path_unknowns_and_failure(self):
        report = arithmetic_report()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            raw = json.dumps(report).encode()
            path.write_bytes(raw)
            value = reader.read_report(path, hashlib.sha256(raw).hexdigest(),
                                       arithmetic_policy()['policy_id'])
            with self.assertRaisesRegex(ValueError, 'does not match requested pin'):
                reader.read_report(path, hashlib.sha256(raw).hexdigest(), observation()['policy_id'])
        self.assertEqual(value['source_report_schema'], report['schema'])
        self.assertEqual(value['public_resource_policy']['resource_revision'], 'r13-arithmetic-facts-v1')
        self.assertFalse(value['scope']['original_r13_campaign_qualified'])
        self.assertFalse(value['scope']['adversarial_key_churn_service_qualified'])
        self.assertFalse(value['native_finite_experiment_criteria_met'])
        for phase in value['phases']:
            actual = phase['receiver']['all_retained_records']['work_arithmetic']
            self.assertEqual([actual[key] for key in ('observed_records', 'unobserved_records',
                'completed_observations', 'unfinished_observations')], [3, 1, 2, 1])
            self.assertEqual(actual['path_counts']['product_reused'], 1)
            self.assertEqual(actual['path_counts']['transcript_completed'], 1)
            self.assertEqual(phase['confirmed_rounds'], 0)
            self.assertFalse(phase['native_phase_criteria_met'])
        source = Path(__file__).resolve().parents[2] / 'trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs'
        self.assertIn('json!("' + report['schema'] + '")', source.read_text())
        # Failed startup retains its separate profile but cannot invent owner or CPU observations.
        report['phases'][0] = dict(mode='baseline', state_backend='authenticated-v1',
            public_resource_policy=arithmetic_policy(), work_profile='arithmetic-facts-v1',
            startup_or_campaign_error='synthetic startup failure')
        self.assertFalse(reader.analyze(report)['phases'][0]['observations_available'])

    def test_arithmetic_report_cannot_claim_raw_policy_schema_owner_or_success(self):
        for edit in (
            lambda r: r.update(schema='native-public-v3-separate-process-campaign-v2'),
            lambda r: r.update(public_resource_policy=observation()),
            lambda r: r.pop('work_profile'),
            lambda r: r.update(original_r13_campaign_qualified=True),
            lambda r: r.update(adversarial_key_churn_service_qualified=True),
            lambda r: r['phases'][0].pop('work_profile'),
            lambda r: r['phases'][0].update(public_resource_policy=observation()),
            lambda r: r['phases'][0].pop('work_arithmetic_owner'),
            lambda r: r['phases'][0]['work_arithmetic_owner'].update(slots=65),
            lambda r: r['phases'][0]['work_arithmetic_owner'].update(initial_state='prewarmed'),
            lambda r: r['phases'][0]['work_arithmetic_owner'].update(retained_software_bytes=3999999),
            lambda r: r['phases'][0]['work_arithmetic_owner'].update(adversarial_key_churn_service_qualified=True),
        ):
            report = arithmetic_report()
            edit(report)
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                reader.analyze(report)

    def test_arithmetic_attributes_do_not_turn_reuse_into_recomputation_or_absence_into_zero(self):
        for edit in (
            lambda v: v.update(completed=False),
            lambda v: v.update(slots=65),
            lambda v: v.update(retained_software_bytes=4194305),
            lambda v: v['arithmetic'].update(lookup_probes=True),
            lambda v: v['arithmetic'].update(publication_probes=65),
            lambda v: v['arithmetic'].update(transcript_entered=True),
            lambda v: v['arithmetic'].update(exact_fact_found=False),
            lambda v: v['arithmetic'].update(trace_reused=False),
            lambda v: v['arithmetic'].update(publication='product'),
        ):
            value = arithmetic_work(reused=True)
            edit(value)
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                reader.arithmetic_observation(value)
        phase = arithmetic_report()['phases'][0]
        phase['public_resource_policy'] = observation()
        del phase['work_profile'], phase['work_arithmetic_owner']
        with self.assertRaisesRegex(ValueError, 'require explicit arithmetic profile'):
            reader.phase_summary(phase)

    def test_historical_derivation_is_explicit_and_cannot_downgrade_paid_cpu_or_policy(self):
        phases = [attribution_phase([], [], [], [record()]) for _ in reader.MODES]
        for phase, mode in zip(phases, reader.MODES):
            phase['mode'] = mode
        report = dict(schema='native-public-v3-separate-process-campaign-v2',
            state_backend='authenticated-v1', finite_experiment_criteria_met=False,
            economics_complete=False, best_observed_cold_legal_method=None,
            preparation=dict(cpu_ns=None, wall_ns=None), phases=phases)
        old_schema = 'pon-public-v3-multiprocess-phase-derivation-v1'
        historical = reader.analyze_for_retained_schema(report, old_schema)
        self.assertEqual(historical['schema'], old_schema)
        self.assertTrue(historical['scope']['cpu_excludes_reactor_authentication_and_response_signing'])
        self.assertNotIn('dispatch_cpu_scope', historical['phases'][0]['receiver'])
        self.assertFalse(historical['native_finite_experiment_criteria_met'])
        self.assertTrue(all(not phase['genuine_budget_depletion_observed']
                            and phase['confirmed_rounds'] == 0
                            and phase['scheduled_confirmation_rounds'] == 3
                            for phase in historical['phases']))
        current = reader.analyze(report)
        self.assertEqual(reader.analyze_for_retained_schema(report, current['schema']), current)
        for unknown in (None, 'pon-public-v3-multiprocess-phase-derivation-v3'):
            with self.assertRaisesRegex(ValueError, 'unknown retained'):
                reader.analyze_for_retained_schema(report, unknown)
        phases[0]['receiver_observation']['schema'] = 'public-v3-local-request-resource-observation-v3'
        with self.assertRaisesRegex(ValueError, 'cannot describe paid-envelope'):
            reader.analyze_for_retained_schema(report, old_schema)
        phases[0]['receiver_observation']['schema'] = 'public-v3-local-request-resource-observation-v2'
        report['public_resource_policy'] = observation()
        with self.assertRaisesRegex(ValueError, 'cannot erase explicit'):
            reader.analyze_for_retained_schema(report, old_schema)

    def test_requested_profile_pin_cannot_relabel_missing_or_mismatched_historical_input(self):
        phases = [attribution_phase([], [], [], [record()]) for _ in reader.MODES]
        for phase, mode in zip(phases, reader.MODES):
            phase['mode'] = mode
        report = dict(schema='native-public-v3-separate-process-campaign-v2',
            state_backend='authenticated-v1', finite_experiment_criteria_met=False,
            economics_complete=False, best_observed_cold_legal_method=None,
            preparation=dict(cpu_ns=None, wall_ns=None), phases=phases)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            def save():
                raw = json.dumps(report).encode()
                path.write_bytes(raw)
                return hashlib.sha256(raw).hexdigest()
            original_hash = save()
            legacy = reader.read_report(path, original_hash)
            self.assertFalse(legacy['native_finite_experiment_criteria_met'])
            with self.assertRaisesRegex(ValueError, 'absent from historical'):
                reader.read_report(path, original_hash, observation()['policy_id'])
            report['public_resource_policy'] = observation()
            for phase in phases:
                phase['public_resource_policy'] = observation()
                phase['completion_work_observation'] = completion_observation()
                phase['receiver_observation'].update(schema='public-v3-local-request-resource-observation-v3',
                    cpu_includes_reactor_authentication_or_response_signing=True,
                    cpu_includes_reactor_authentication=False,
                    dispatch_cpu_includes_paid_body_decode=True,
                    dispatch_cpu_includes_response_signing=True)
            current_hash = save()
            current = reader.read_report(path, current_hash, observation()['policy_id'])
            self.assertFalse(current['native_finite_experiment_criteria_met'])
            with self.assertRaisesRegex(ValueError, 'does not match requested pin'):
                reader.read_report(path, current_hash, observation('r11')['policy_id'])
            phases[1]['public_resource_policy'] = observation('r11')
            with self.assertRaisesRegex(ValueError, 'mixed or missing'):
                reader.read_report(path, save())
            # Explicit null means a normal observed phase, not a startup error
            # permitting mixed/missing policy metadata under the requested pin.
            phases[1]['startup_or_campaign_error'] = None
            with self.assertRaisesRegex(ValueError, 'mixed or missing'):
                reader.read_report(path, save(), observation()['policy_id'])
            del phases[1]['public_resource_policy']
            with self.assertRaisesRegex(ValueError, 'mixed or missing'):
                reader.read_report(path, save(), observation()['policy_id'])

    def test_exact_policy_metadata_distinguishes_r11_r12_r13_and_does_not_relabel_history(self):
        phase = attribution_phase([], [], [], [record()])
        self.assertNotIn('public_resource_policy', reader.phase_summary(phase))
        phase['public_resource_policy'] = observation('r10')
        self.assertEqual(reader.phase_summary(phase)['public_resource_policy']['resource_revision'], 'r10')
        phase['receiver_observation'].update(schema='public-v3-local-request-resource-observation-v3',
            cpu_includes_reactor_authentication_or_response_signing=True,
            cpu_includes_reactor_authentication=False,
            dispatch_cpu_includes_paid_body_decode=True,
            dispatch_cpu_includes_response_signing=True)
        with self.assertRaisesRegex(ValueError, 'CPU scope disagree'):
            reader.phase_summary(phase)
        for revision in ('r11', 'r12', 'r13'):
            phase['public_resource_policy'] = observation(revision)
            if revision == 'r13':
                phase['completion_work_observation'] = completion_observation()
            readback = reader.phase_summary(phase)
            self.assertEqual(readback['public_resource_policy']['resource_revision'], revision)
            self.assertFalse(readback['genuine_budget_depletion_observed'])
            self.assertFalse(readback['native_phase_criteria_met'])
        phase['public_resource_policy']['policy_id'] = '0' * 64
        with self.assertRaises(ValueError):
            reader.phase_summary(phase)

    def test_r13_registry_scope_is_bounded_explicit_and_never_added_to_r12(self):
        phase = attribution_phase([], [], [], [record()])
        phase['receiver_observation'].update(schema='public-v3-local-request-resource-observation-v3',
            cpu_includes_reactor_authentication_or_response_signing=True,
            cpu_includes_reactor_authentication=False, dispatch_cpu_includes_paid_body_decode=True,
            dispatch_cpu_includes_response_signing=True)
        phase['public_resource_policy'] = observation('r12')
        historical = reader.phase_summary(phase)
        self.assertNotIn('completion_work_observation', historical)
        phase['completion_work_observation'] = completion_observation()
        with self.assertRaisesRegex(ValueError, 'requires explicit r13'):
            reader.phase_summary(phase)
        phase['public_resource_policy'] = observation('r13')
        self.assertEqual(reader.phase_summary(phase)['completion_work_observation'], completion_observation())
        for change in ({'survives_process_restart': True}, {'identity_capacity': 8192},
                       {'retained_identities': 4097}, {'live_completions': 3},
                       {'full_capacity_skips': None}, {'evicts_live_epoch_identities': True},
                       {'epoch_scope': 'per-connection'}, {'identity_storage_bytes': True}):
            phase['completion_work_observation'] = {**completion_observation(), **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                reader.phase_summary(phase)
        phase['completion_work_observation'] = None
        with self.assertRaises(ValueError):
            reader.phase_summary(phase)
        del phase['completion_work_observation']
        with self.assertRaises(ValueError):
            reader.phase_summary(phase)

    def test_paid_envelope_v3_requires_exact_scope_and_preserves_legacy_meaning(self):
        phase = attribution_phase([], [], [], [record()])
        legacy = reader.phase_summary(phase)
        self.assertEqual(legacy['receiver']['dispatch_cpu_scope'], 'native-dispatch-only')
        observer = phase['receiver_observation']
        observer.update(schema='public-v3-local-request-resource-observation-v3',
                        cpu_includes_reactor_authentication_or_response_signing=True,
                        cpu_includes_reactor_authentication=False,
                        dispatch_cpu_includes_paid_body_decode=True,
                        dispatch_cpu_includes_response_signing=True)
        current = reader.phase_summary(phase)
        self.assertEqual(current['receiver']['dispatch_cpu_scope'],
                         'paid-body-decode-native-dispatch-signed-response')
        self.assertFalse(current['genuine_budget_depletion_observed'])
        for key in ('cpu_includes_reactor_authentication_or_response_signing',
                    'cpu_includes_reactor_authentication',
                    'dispatch_cpu_includes_paid_body_decode',
                    'dispatch_cpu_includes_response_signing'):
            previous = observer[key]
            observer[key] = not previous
            with self.subTest(key=key), self.assertRaises(ValueError):
                reader.phase_summary(phase)
            observer[key] = previous

    def test_unknown_body_digest_never_becomes_a_role_identity(self):
        for caller_role in range(3):
            for retained_null in (False, True):
                with self.subTest(caller_role=caller_role, retained_null=retained_null):
                    calls = [[], [], []]
                    calls[caller_role] = [attribution_call(None)]
                    observed = record()
                    if retained_null:
                        observed['body_digest'] = None
                    value = reader.phase_summary(attribution_phase(*calls, [observed]))
                    groups = value['receiver']['by_observed_body_role']
                    self.assertEqual(set(groups), {'unattributed_or_ambiguous'})
                    self.assertEqual(groups['unattributed_or_ambiguous']['records'], 1)

    def test_known_body_role_does_not_absorb_unknown_receiver_records(self):
        body = '01' * 32
        observed = [{**record(), 'body_digest': [1] * 32}, record()]
        value = reader.phase_summary(attribution_phase(
            [attribution_call(body)], [], [attribution_call(None)], observed))
        groups = value['receiver']['by_observed_body_role']
        self.assertEqual(set(groups), {'honest_submit', 'unattributed_or_ambiguous'})
        self.assertEqual(groups['honest_submit']['records'], 1)
        self.assertEqual(groups['unattributed_or_ambiguous']['records'], 1)

    def test_same_known_body_across_roles_stays_ambiguous(self):
        body = '02' * 32
        value = reader.phase_summary(attribution_phase(
            [attribution_call(body)], [], [attribution_call([2] * 32)],
            [{**record(), 'body_digest': body}]))
        groups = value['receiver']['by_observed_body_role']
        self.assertEqual(set(groups), {'unattributed_or_ambiguous'})
        self.assertEqual(groups['unattributed_or_ambiguous']['records'], 1)

    def test_zero_body_digest_is_known_but_malformed_digest_rejects(self):
        value = reader.phase_summary(attribution_phase(
            [], [attribution_call('00' * 32)], [],
            [{**record(), 'body_digest': [0] * 32}]))
        self.assertEqual(set(value['receiver']['by_observed_body_role']), {'client_history'})
        for invalid in ('unknown', [0] * 31):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, 'digest'):
                reader.phase_summary(attribution_phase(
                    [attribution_call(invalid)], [], [], [record()]))

    def test_nested_native_refusal_and_legacy_error_preserve_real_cause(self):
        def row(response):
            return {'status': 'refused', 'returned_after_window': False,
                    'response': response, 'error': None}
        errors = reader.call_summary([
            row({'ok': False, 'value': {'error': 'PUBLIC_MUTATION_CPU_BUDGET'}}),
            row({'error': 'LEGACY_REJECTION'}), row(None),
            row({'error': 'SAME', 'value': {'error': 'SAME'}}),
        ])['refusals']
        self.assertEqual(errors, {'PUBLIC_MUTATION_CPU_BUDGET': 1,
                                  'LEGACY_REJECTION': 1, 'None': 1, 'SAME': 1})
        for malformed in [
            {'error': 'FLAT', 'value': {'error': 'NESTED'}},
            {'value': {'error': {'invented': 'classification'}}},
            {'value': 'not an envelope'},
        ]:
            with self.assertRaises(ValueError):
                reader.call_summary([row(malformed)])

    def test_late_ack_is_separate_from_on_time_and_confirmation(self):
        rows = [{'status': 'ok', 'returned_after_window': late, 'packet_index': 0,
                 'elapsed_wall_ns': 12, 'calling_process_cpu_ns': None} for late in (False, True)]
        value = reader.call_summary(rows)
        self.assertEqual(value['attempts'], 2)
        self.assertEqual(value['acknowledged_on_time'], 1)
        self.assertEqual(value['acknowledged_after_window'], 1)
        self.assertEqual(value['on_time_unique_packet_indices'], [0])
        self.assertEqual(value['calling_process_cpu_ns']['unknown_count'], 2)
        self.assertNotIn('confirmed', value)

    def test_v1_does_not_fabricate_phase_cost_from_dispatch(self):
        row = record()
        del row['submit_phases']
        value = reader.execution_summary([row], False)
        self.assertIsNone(value['submit_phases'])
        self.assertFalse(value['submit_phase_measurements_available'])
        self.assertEqual(value['dispatch_thread_cpu_ns']['sum_known_ns'], 100)
        self.assertEqual(value['full_work_thread_cpu_ns']['sum_known_ns'], 30)
        self.assertNotIn('total_cpu_ns', value)

    def test_unentered_and_entered_unknown_cpu_are_distinct(self):
        row = record()
        row['submit_phases'][2].update(started=True, completed=True, accepted=False,
                                       wall_ns=150, thread_cpu_ns=None)
        value = reader.execution_summary([row], True)['submit_phases']
        self.assertEqual(value[2]['thread_cpu_ns']['unknown_count'], 1)
        self.assertEqual(value[2]['outcomes'], {'rejected': 1})
        self.assertEqual(value[3]['not_started'], 1)
        self.assertEqual(value[3]['thread_cpu_ns']['unknown_count'], 0)
        self.assertIsNone(value[3]['thread_cpu_ns']['mean_known_ns'])

    def test_unfinished_outcome_is_not_successful_or_rejected(self):
        row = record()
        row['complete'] = False
        row['submit_phases'][4].update(started=True, wall_ns=500, thread_cpu_ns=5)
        value = reader.execution_summary([row], True)
        phase = value['submit_phases'][4]
        self.assertEqual(value['record_complete'], 0)
        self.assertEqual((phase['started'], phase['completed'], phase['unfinished']), (1, 0, 1))
        self.assertEqual(phase['outcomes'], {'unknown': 1})
        self.assertEqual(phase['wall_ns']['sum_known_ns'], 500)

    def test_missing_v2_phase_slot_rejects(self):
        row = record()
        row['submit_phases'].pop()
        with self.assertRaisesRegex(ValueError, 'seven ordered'):
            reader.execution_summary([row], True)

    def test_failed_startup_does_not_change_fixed_round_denominator(self):
        value = reader.phase_summary({'mode': 'baseline', 'state_backend': 'authenticated-v1',
                                      'startup_or_campaign_error': 'preserved native startup failure'})
        self.assertEqual(value['scheduled_confirmation_rounds'], 3)
        self.assertIsNone(value['confirmed_rounds'])
        self.assertFalse(value['observations_available'])

    def test_repeated_confirmation_round_and_inflated_aggregate_reject(self):
        phase = {'mode': 'baseline', 'state_backend': 'authenticated-v1', 'duration_seconds': 30,
                 'confirmations': [{'round': 0, 'confirmed_inside_pressure_window': True}] * 2,
                 'all_signed_rounds_confirmed_in_window': True}
        with self.assertRaisesRegex(ValueError, 'unique scheduled'):
            reader.phase_summary(phase)
        phase['confirmations'].pop()
        with self.assertRaisesRegex(ValueError, 'aggregate'):
            reader.phase_summary(phase)

    def test_exact_hash_mismatch_rejects_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            raw = b'{"not":"native evidence"}\n'
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
                reader.read_report(path, '00' * 32)
            self.assertEqual(path.read_bytes(), raw)

    def test_boolean_and_negative_timing_are_not_integer_cpu(self):
        for value in (-1, True, 1.5):
            with self.assertRaises(ValueError):
                reader.stats([value])


if __name__ == '__main__':
    unittest.main()
