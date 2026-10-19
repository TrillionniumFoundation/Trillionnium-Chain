#!/usr/bin/env python3
"""Reader counterexamples only; these synthetic records are not native evidence."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_public_v3_phase_read as reader


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


def attribution_call(body_digest):
    return {'status': 'refused', 'returned_after_window': False,
            'public_request_body_digest': body_digest,
            'response': {'value': {'error': 'SYNTHETIC_CONTROL'}}, 'error': None}


class ReaderTests(unittest.TestCase):
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
