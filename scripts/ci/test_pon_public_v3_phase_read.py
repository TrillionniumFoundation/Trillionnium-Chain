#!/usr/bin/env python3
"""Reader counterexamples only; these synthetic records are not native evidence."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

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


def record_v4():
    row = record()
    row['submit_phases'] = [dict(phase=phase, started=False, completed=False,
        accepted=None, error_code=None, started_ns=None, ended_ns=None, wall_ns=None,
        thread_cpu_ns=None, parent_phase=reader.PHASE_PARENTS_V4.get(phase))
        for phase in reader.PHASES_V4]
    for field in reader.WAIT_FIELDS_V4:
        row[field] = dict(started_ns=None, ended_ns=None, wall_ns=None,
                          completed=False, accepted=None, error_code=None)
    row['terminal_error_code'] = None
    return row


def settlement_record(**facts):
    """Synthetic reader control only; no native work or CPU measurement."""
    row = record_v4()
    value = dict(schema=reader.CPU_SETTLEMENT_SCHEMA, owner_cpu_known=True,
        scoped_worker_cpu_known=True, live_paid_cpu_known=True, residual_cpu_known=True,
        budget_settled=True, continuous_journal_persisted=None, has_control_authority=False,
        interval_is_additive_to_dispatch_cpu=False)
    value.update(facts)
    row['cpu_settlement'] = value
    accepted = all(value[key] for key in (*reader.CPU_SETTLEMENT_KNOWN_FIELDS, 'budget_settled')) \
        and value['continuous_journal_persisted'] is not False
    row['submit_phases'][reader.PHASES_V4.index('cpu_settle')].update(started=True,
        completed=True, accepted=accepted, started_ns=100, ended_ns=110, wall_ns=10, thread_cpu_ns=3)
    return row


def settlement_values_record(**facts):
    """Original-sample field controls; these values are not native evidence."""
    row = settlement_record()
    row['cpu_settlement'].update(schema=reader.CPU_SETTLEMENT_VALUES_SCHEMA,
        owner_cpu_ns=100, scoped_worker_cpu_ns=70, total_cpu_ns=170,
        live_paid_cpu_ns=150, residual_cpu_ns=20, **facts)
    return row


def lifecycle_record(*, accepted=10, connection=40, task=90, created=True, failed=False):
    row = settlement_values_record()
    row.update(lifecycle=dict(schema='public-v3-request-lifecycle-v1', accepted_ns=accepted,
        connection_closed_ns=connection, task_closed_ns=task,
        clock_is_observer_local=True, has_control_authority=False),
        connection_closed=connection is not None, task_created=created, task_closed=task is not None,
        observation_failed=failed,
        complete=connection is not None and (not created or task is not None) and not failed)
    return row


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


def observed_history_call():
    """Synthetic failed import sharing the existing History validator fixture."""
    from test_run_from_zero_native import simulated_import_observation
    native = simulated_import_observation()
    row = attribution_call('ab' * 32)
    row.update(status='ok', request=dict(op='history', tip='01' * 32, after='02' * 32),
        response={'value': {'packets': ['synthetic-not-a-native-packet']}},
        client_import=dict(started_ns=1000, ended_ns=1100, wall_ns=99, thread_cpu_ns=9,
            thread_cpu_observation_available=True, succeeded=False, error='PUBLIC_REQUEST_DEADLINE',
            operation='synthetic full import interval', native_import_observation=native,
            scope='calling client thread only; excludes scoped execution worker CPU; '
                  'unknown clock is null; no deadline or acceptance authority'))
    return row


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


def diagnostic_record():
    row = record_v4()
    row.update(dispatch_error_code=None, terminal_phase='response',
        error_diagnostics=dict(schema=reader.ERROR_DIAGNOSTIC_SCHEMA,
            has_control_authority=False, messages_are_untrusted=True, message_capacity_bytes=96,
            dispatch=dict(kind='unclassified', message_prefix='ROOT', message_truncated=False),
            terminal=None))
    return row


class ReaderTests(unittest.TestCase):
    @staticmethod
    def wait_slot(duration, *, accepted=True, completed=True, code=None):
        return dict(started_ns=0, ended_ns=duration, wall_ns=duration,
                    completed=completed, accepted=accepted, error_code=code)

    def test_per_request_queue_p99_is_order_statistic_not_waiter_total(self):
        rows = []
        for duration in range(1, 101):
            row = record_v4()
            row['paid_task_queue_wait'] = self.wait_slot(duration)
            rows.append(row)
        result = reader.execution_summary(rows, True, observer_v4=True)
        wait = result['wait_intervals']['paid_task_queue_wait']
        self.assertEqual(wait['wall_ns']['sum_known_ns'], 5050)
        detail = wait['interval_outcomes']
        self.assertEqual(detail['p99_all_retained_entered_terminal_ns'], 99)
        self.assertEqual(detail['terminal_wall_ns']['known_count'], 100)
        self.assertEqual(detail['terminal_by_outcome']['accepted']['p99_all_terminal_records_ns'], 99)
        self.assertIsNone(detail['terminal_by_outcome']['rejected']['p99_all_terminal_records_ns'])
        self.assertIsNone(detail['scope']['whole_request_population_p99_ns'])
        self.assertTrue(detail['scope']['cumulative_waiter_time_is_not_request_p99'])

    def test_unfinished_elapsed_does_not_enter_terminal_tail_or_erase_failure(self):
        rows = [record_v4() for _ in range(4)]
        rows[0]['paid_task_queue_wait'] = self.wait_slot(7)
        rows[1]['paid_task_queue_wait'] = self.wait_slot(19, accepted=False,
                                                       code='PUBLIC_REQUEST_CANCELLED')
        rows[2]['paid_task_queue_wait'] = self.wait_slot(1000000, accepted=None, completed=False)
        before = copy.deepcopy(rows)
        detail = reader.execution_summary(rows, True, observer_v4=True)[
            'wait_intervals']['paid_task_queue_wait']['interval_outcomes']
        self.assertEqual(rows, before)
        self.assertEqual((detail['slots'], detail['entered'], detail['terminal_records'],
                          detail['unfinished_records'], detail['unentered_or_entry_clock_unknown']),
                         (4, 3, 2, 1, 1))
        self.assertEqual(detail['terminal_wall_ns']['p99_all_terminal_records_ns'], 19)
        self.assertEqual(detail['terminal_by_outcome']['rejected']['known_count'], 1)
        self.assertEqual(detail['typed_cancelled_terminal_records'], 1)
        self.assertEqual(detail['unfinished_observed_elapsed_wall_ns']['sum_known_ns'], 1000000)
        self.assertIsNone(detail['p99_all_retained_entered_terminal_ns'])

    def test_missing_terminal_clock_cannot_produce_all_terminal_p99(self):
        rows = [record_v4(), record_v4()]
        rows[0]['paid_task_queue_wait'] = self.wait_slot(7)
        rows[1]['paid_task_queue_wait'] = self.wait_slot(None, accepted=False,
                                                        code='PUBLIC_REQUEST_DEADLINE')
        detail = reader.execution_summary(rows, True, observer_v4=True)[
            'wait_intervals']['paid_task_queue_wait']['interval_outcomes']
        self.assertEqual(detail['terminal_records'], 2)
        self.assertEqual(detail['terminal_wall_ns']['unknown_count'], 1)
        self.assertIsNone(detail['terminal_wall_ns']['p99_all_terminal_records_ns'])
        self.assertIsNone(detail['p99_all_retained_entered_terminal_ns'])
        self.assertEqual(detail['typed_terminal_error_counts']['PUBLIC_REQUEST_DEADLINE'], 1)
        self.assertEqual(detail['typed_cancelled_terminal_records'], 0)

    def test_phase_tails_preserve_unknown_outcomes_and_inclusive_costs(self):
        rows = [record(), record(), record()]
        rows[0]['submit_phases'][2].update(started=True, completed=True, accepted=False,
                                           wall_ns=11, thread_cpu_ns=3)
        rows[1]['submit_phases'][2].update(started=True, wall_ns=500, thread_cpu_ns=5)
        result = reader.execution_summary(rows, True)['submit_phases'][2]
        self.assertEqual(result['wall_ns']['sum_known_ns'], 511)
        self.assertEqual(result['thread_cpu_ns']['sum_known_ns'], 8)
        detail = result['interval_outcomes']
        self.assertEqual(detail['terminal_wall_ns']['p99_all_terminal_records_ns'], 11)
        self.assertEqual(detail['unfinished_observed_elapsed_wall_ns']['known_count'], 1)
        self.assertIsNone(detail['p99_all_retained_entered_terminal_ns'])
        self.assertTrue(detail['scope']['inclusive_stages_are_not_additive'])
        empty = reader.interval_outcome_summary([])
        self.assertEqual(empty['entered'], 0)
        self.assertIsNone(empty['p99_all_retained_entered_terminal_ns'])

    def test_current_derivation_separates_unobserved_startup_rounds_and_preserves_v2(self):
        phases = [attribution_phase([], [], [], [record()]) for _ in reader.MODES]
        for phase, mode in zip(phases, reader.MODES):
            phase['mode'] = mode
        phases[2] = dict(mode='late-product', state_backend='authenticated-v1',
                         startup_or_campaign_error='original native failure')
        report = dict(schema='native-public-v3-separate-process-campaign-v2',
            state_backend='authenticated-v1', finite_experiment_criteria_met=False,
            economics_complete=False, best_observed_cold_legal_method=None,
            preparation=dict(cpu_ns=None, wall_ns=None), phases=phases)
        current = reader.analyze(report)
        self.assertEqual(current['schema'], 'pon-public-v3-multiprocess-phase-derivation-v3')
        self.assertEqual(current['phases'][2]['observed_confirmation_rounds'], 0)
        self.assertEqual(current['phases'][2]['unobserved_scheduled_rounds'], 3)
        self.assertIsNone(current['phases'][2]['confirmed_rounds'])
        old = reader.analyze_for_retained_schema(report, 'pon-public-v3-multiprocess-phase-derivation-v2')
        self.assertNotIn('unobserved_scheduled_rounds', old['phases'][2])
        self.assertNotIn('interval_outcomes', old['phases'][0]['receiver'][
            'all_retained_records']['submit_phases'][0])
        self.assertEqual(old['phases'][0]['receiver']['all_retained_records']['submit_phases'][0][
            'wall_ns'], current['phases'][0]['receiver']['all_retained_records']['submit_phases'][0]['wall_ns'])
        self.assertEqual(reader.analyze_for_retained_schema(report, current['schema']), current)

    def test_request_error_diagnostic_extension_retains_legacy_unknown_and_typed_separation(self):
        measured = diagnostic_record()
        remote = diagnostic_record()
        remote['error_diagnostics']['dispatch']['kind'] = 'remote_refusal'
        cancelled = diagnostic_record()
        cancelled['dispatch_error_code'] = 'PUBLIC_REQUEST_CANCELLED'
        cancelled['error_diagnostics']['dispatch'].update(
            kind='cancelled', message_prefix='receiver diagnostic text changed')
        abandoned = diagnostic_record()
        abandoned.update(dispatch_started=False, dispatch_accepted=None)
        abandoned['error_diagnostics']['dispatch'] = None
        rows = [record_v4(), measured, remote, cancelled, abandoned]
        before = copy.deepcopy(rows)
        result = reader.execution_summary(rows, True, observer_v4=True)
        self.assertEqual(rows, before)
        detail = result['error_diagnostics']
        self.assertEqual(detail['observed_records'], 4)
        self.assertEqual(detail['historical_records_without_extension'], 1)
        self.assertEqual(detail['dispatch']['diagnostics_present'], 3)
        self.assertEqual(detail['dispatch']['no_diagnostic_captured'], 1)
        kinds = {row['kind']: row for row in detail['dispatch']['counts']}
        self.assertIsNone(kinds['unclassified']['typed_error_code'])
        self.assertIsNone(kinds['remote_refusal']['typed_error_code'])
        self.assertEqual(kinds['cancelled']['typed_error_code'], 'PUBLIC_REQUEST_CANCELLED')
        self.assertEqual(result['dispatch_outcomes'], {'rejected': 4, 'unknown': 1})
        self.assertNotIn('error_diagnostics', reader.execution_summary([record_v4()], True, observer_v4=True))
        with self.assertRaisesRegex(ValueError, 'v4 observer scope'):
            reader.execution_summary([measured], True)

    def test_request_error_diagnostic_keeps_distinct_terminal_cause_and_truncation(self):
        row = diagnostic_record()
        row.update(terminal_phase='work', terminal_error_code='PUBLIC_EOF')
        row['error_diagnostics']['terminal'] = dict(kind='transport',
            message_prefix='PUBLIC_EOF', message_truncated=False)
        value = reader.execution_summary([row], True, observer_v4=True)['error_diagnostics']
        self.assertEqual(value['dispatch']['counts'][0]['message_prefix'], 'ROOT')
        self.assertIsNone(value['dispatch']['counts'][0]['typed_error_code'])
        self.assertEqual(value['terminal']['counts'][0]['typed_error_code'], 'PUBLIC_EOF')
        for text in ('x' * 96, 'x' * 95, '界' * 31):
            row['error_diagnostics']['dispatch'].update(message_prefix=text, message_truncated=True)
            reader.execution_summary([row], True, observer_v4=True)

    def test_request_error_diagnostic_keeps_predispatch_errors_and_legal_kind_overrides(self):
        for code, kind in (
            ('PUBLIC_MUTATION_CPU_BUDGET', 'capacity'),
            ('PUBLIC_EOF', 'transport'),
            ('PUBLIC_EOF', 'local_structure'),
            ('REMOTE_TERMINAL', 'remote_refusal'),
            ('REMOTE_RETRYABLE', 'remote_refusal'),
            ('REMOTE_TERMINAL', 'local_structure'),
            ('ANCESTRY_INDEX_BUDGET', 'capacity'),
        ):
            row = diagnostic_record()
            row.update(dispatch_started=False, dispatch_accepted=None, dispatch_error_code=code)
            # Display text is deliberately independent of code and kind. This
            # synthetic record does not authenticate a remote or local origin.
            row['error_diagnostics']['dispatch'].update(kind=kind, message_prefix='ROOT')
            before = copy.deepcopy(row)
            with self.subTest(code=code, kind=kind):
                value = reader.execution_summary([row], True, observer_v4=True)
                self.assertEqual(row, before)
                self.assertEqual(value['dispatch_outcomes'], {'unknown': 1})
                item = value['error_diagnostics']['dispatch']['counts'][0]
                self.assertEqual((item['typed_error_code'], item['kind'], item['message_prefix']),
                                 (code, kind, 'ROOT'))

    def test_request_error_diagnostic_rejects_bad_scope_unbounded_or_reclassified_data(self):
        mutations = [
            lambda r: r['error_diagnostics'].update(schema='unknown'),
            lambda r: r['error_diagnostics'].update(has_control_authority=True),
            lambda r: r['error_diagnostics'].update(messages_are_untrusted=False),
            lambda r: r['error_diagnostics'].update(message_capacity_bytes=97),
            lambda r: r['error_diagnostics'].update(extra=True),
            lambda r: r['error_diagnostics']['dispatch'].update(kind='root-authority'),
            lambda r: r['error_diagnostics']['dispatch'].update(message_prefix='x' * 97),
            lambda r: r['error_diagnostics']['dispatch'].update(message_prefix='界' * 33),
            lambda r: r['error_diagnostics']['dispatch'].update(message_truncated=1),
            lambda r: r['error_diagnostics']['dispatch'].update(message_truncated=True),
            lambda r: r['error_diagnostics']['dispatch'].update(typed_code='ROOT'),
            lambda r: r.update(dispatch_accepted=True),
            lambda r: r.pop('dispatch_error_code'),
            lambda r: r.update(dispatch_error_code='WORK:Transcript'),
            lambda r: r.update(terminal_error_code='PUBLIC_EOF'),
            lambda r: r.update(dispatch_error_code='ROOT'),
            lambda r: (r.update(dispatch_error_code='ROOT'),
                       r['error_diagnostics']['dispatch'].update(kind='protocol_invalid')),
            lambda r: (r.update(dispatch_error_code='PUBLIC_EOF'),
                       r['error_diagnostics']['dispatch'].update(kind='cancelled')),
            lambda r: (r.update(dispatch_error_code='REMOTE_TERMINAL'),
                       r['error_diagnostics']['dispatch'].update(kind='transport')),
            lambda r: (r.update(dispatch_error_code='PUBLIC_REQUEST_CANCELLED'),
                       r['error_diagnostics']['dispatch'].update(kind='remote_refusal')),
        ]
        for index, mutate in enumerate(mutations):
            row = diagnostic_record()
            mutate(row)
            with self.subTest(index=index), self.assertRaises(ValueError):
                reader.execution_summary([row], True, observer_v4=True)

    def test_cpu_settlement_keeps_native_outcomes_unknowns_and_separate_failure_causes(self):
        success = settlement_record()
        persisted = settlement_record(continuous_journal_persisted=True)
        clock_failed = settlement_record(owner_cpu_known=False, residual_cpu_known=False)
        budget_failed = settlement_record(budget_settled=False)
        journal_failed = settlement_record(continuous_journal_persisted=False)
        # Native ACK/rejection is independent of settlement success or failure.
        clock_failed['dispatch_accepted'] = True
        journal_failed['dispatch_accepted'] = True
        rows = [record_v4(), success, persisted, clock_failed, budget_failed, journal_failed]
        before = copy.deepcopy(rows)
        result = reader.execution_summary(rows, True, observer_v4=True)
        self.assertEqual(rows, before)
        self.assertEqual(result['dispatch_outcomes'], {'rejected': 4, 'accepted': 2})
        detail = result['cpu_settlement']
        self.assertEqual((detail['observed_records'], detail['records_without_settlement_extension']), (5, 1))
        self.assertEqual((detail['succeeded'], detail['failed']), (2, 3))
        self.assertEqual((detail['budget_settled'], detail['budget_not_settled']), (4, 1))
        self.assertEqual(detail['cpu_known_counts'], dict(owner_cpu_known=4, scoped_worker_cpu_known=5,
                                                        live_paid_cpu_known=5, residual_cpu_known=4))
        self.assertEqual(detail['continuous_journal'], dict(persisted=1, failed=1, no_scope=3))
        phase = result['submit_phases'][reader.PHASES_V4.index('cpu_settle')]
        self.assertEqual((phase['started'], phase['not_started'], phase['completed']), (5, 1, 5))
        self.assertEqual(phase['outcomes'], {'accepted': 2, 'rejected': 3})
        for row in rows[1:]:
            del row['cpu_settlement']
            # An absent historical extension does not invalidate a legacy
            # accepted/rejected CpuSettle or invent its budget/journal facts.
            self.assertNotIn('cpu_settlement', reader.execution_summary([row], True, observer_v4=True))

    def test_cpu_settlement_rejects_bad_scope_types_and_inconsistent_or_missing_phase(self):
        mutations = [
            lambda r: r.update(cpu_settlement=None),
            lambda r: r['cpu_settlement'].update(schema='unknown'),
            lambda r: r['cpu_settlement'].update(has_control_authority=True),
            lambda r: r['cpu_settlement'].update(has_control_authority=0),
            lambda r: r['cpu_settlement'].update(interval_is_additive_to_dispatch_cpu=True),
            lambda r: r['cpu_settlement'].update(interval_is_additive_to_dispatch_cpu=0),
            lambda r: r['cpu_settlement'].update(continuous_journal_persisted=1),
            lambda r: r['cpu_settlement'].update(continuous_journal_persisted='true'),
            lambda r: r['cpu_settlement'].pop('continuous_journal_persisted'),
            lambda r: r['cpu_settlement'].update(extra=True),
            lambda r: r.pop('submit_phases'),
            lambda r: r['submit_phases'].pop(reader.PHASES_V4.index('cpu_settle')),
            lambda r: r['submit_phases'].__setitem__(reader.PHASES_V4.index('cpu_settle'),
                           record_v4()['submit_phases'][reader.PHASES_V4.index('cpu_settle')]),
            lambda r: r['submit_phases'][reader.PHASES_V4.index('cpu_settle')].update(
                           completed=False, accepted=None),
            lambda r: r['submit_phases'][reader.PHASES_V4.index('cpu_settle')].update(accepted=False),
            lambda r: r['cpu_settlement'].update(continuous_journal_persisted=False),
        ]
        for key in (*reader.CPU_SETTLEMENT_KNOWN_FIELDS, 'budget_settled'):
            for invalid in (False, 1, None, 'true'):
                mutations.append(lambda r, key=key, invalid=invalid: r['cpu_settlement'].update({key: invalid}))
        for index, mutate in enumerate(mutations):
            row = settlement_record()
            mutate(row)
            with self.subTest(index=index), self.assertRaises(ValueError):
                reader.execution_summary([row], True, observer_v4=True)
        for instrumented, observer_v4 in ((True, False), (False, False), (False, True)):
            with self.subTest(instrumented=instrumented, observer_v4=observer_v4), \
                    self.assertRaisesRegex(ValueError, 'v4 observer scope'):
                reader.execution_summary([settlement_record()], instrumented, observer_v4=observer_v4)

    def test_cpu_settlement_scope_changes_only_reports_with_the_optional_extension(self):
        row = settlement_record()
        del row['cpu_settlement']
        phases = [attribution_phase([], [], [], [copy.deepcopy(row)]) for _ in reader.MODES]
        for phase, mode in zip(phases, reader.MODES):
            phase['mode'] = mode
            phase['receiver_observation'].update(schema='public-v3-local-request-resource-observation-v4',
                cpu_includes_reactor_authentication_or_response_signing=True,
                cpu_includes_reactor_authentication=False, dispatch_cpu_includes_paid_body_decode=True,
                dispatch_cpu_includes_response_signing=True, phase_parent_links_are_inclusive=True,
                cpu_wait_is_outside_dispatch=True, monotonic_epoch_is_observer_local=True)
        report = dict(schema='native-public-v3-separate-process-campaign-v2',
            state_backend='authenticated-v1', finite_experiment_criteria_met=False,
            economics_complete=False, best_observed_cold_legal_method=None,
            preparation=dict(cpu_ns=None, wall_ns=None), phases=phases)
        legacy = reader.analyze(report)
        self.assertTrue(legacy['scope']['submit_phase_cpu_excludes_response_signing'])
        self.assertNotIn('submit_phase_cpu_scope_is_phase_specific', legacy['scope'])
        report['phases'][0]['receiver_observation']['records'][0]['cpu_settlement'] = \
            settlement_record()['cpu_settlement']
        current = reader.analyze(report)
        self.assertFalse(current['scope']['submit_phase_cpu_excludes_response_signing'])
        self.assertFalse(current['scope']['cpu_intervals_are_nested_not_additive'])
        self.assertTrue(current['scope']['cpu_intervals_are_not_additive'])
        self.assertTrue(current['scope']['submit_phase_cpu_scope_is_phase_specific'])
        self.assertTrue(current['phases'][0]['receiver']['all_retained_records']['cpu_settlement'][
            'scope']['interval_overlaps_dispatch_cpu'])
        self.assertFalse(current['phases'][0]['receiver']['all_retained_records']['cpu_settlement'][
            'scope']['interval_is_additive_to_dispatch_cpu'])
        # The new optional facts and their scope are the only derivation changes;
        # every old phase measurement, outcome and denominator remains identical.
        restored = copy.deepcopy(current)
        restored['scope'] = legacy['scope']
        receiver = restored['phases'][0]['receiver']
        del receiver['all_retained_records']['cpu_settlement']
        del receiver['by_observed_body_role']['unattributed_or_ambiguous']['cpu_settlement']
        self.assertEqual(json.dumps(restored, sort_keys=True), json.dumps(legacy, sort_keys=True))
        del report['phases'][0]['receiver_observation']['records'][0]['cpu_settlement']
        self.assertEqual(json.dumps(reader.analyze(report), sort_keys=True), json.dumps(legacy, sort_keys=True))

    def test_original_settlement_values_keep_all_costs_outcomes_and_unknown_denominators(self):
        rejected = settlement_values_record()
        rejected['dispatch_error_code'] = 'PUBLIC_REQUEST_CANCELLED'
        accepted = settlement_values_record(budget_settled=False)
        accepted['dispatch_accepted'] = True
        accepted['submit_phases'][reader.PHASES_V4.index('cpu_settle')]['accepted'] = False
        unknown = settlement_values_record()
        unknown.update(dispatch_accepted=None, dispatch_thread_cpu_ns=None)
        unknown['cpu_settlement'].update(owner_cpu_ns=None, owner_cpu_known=False,
            total_cpu_ns=None, residual_cpu_ns=None, residual_cpu_known=False, budget_settled=False)
        unknown['submit_phases'][reader.PHASES_V4.index('cpu_settle')]['accepted'] = False
        rows = [rejected, accepted, unknown, settlement_record(), record_v4()]
        before = copy.deepcopy(rows)
        result = reader.execution_summary(rows, True, observer_v4=True)
        self.assertEqual(rows, before)
        values = result['cpu_settlement']['original_cpu_samples']
        self.assertEqual((values['retained_records'], values['settlements_with_values'],
                          values['legacy_settlements_without_values'], values['records_without_settlement']),
                         (5, 3, 1, 1))
        total = values['values_ns']['total_cpu_ns']
        self.assertEqual((total['known_count'], total['unknown_count'], total['sum_known_ns']), (2, 3, 340))
        self.assertEqual(values['values_ns']['scoped_worker_cpu_ns']['sum_known_ns'], 210)
        self.assertEqual(values['by_dispatch_outcome']['rejected']['records'], 3)
        self.assertEqual(values['by_dispatch_outcome']['rejected']['total_cpu_ns']['sum_known_ns'], 170)
        self.assertEqual(values['by_dispatch_outcome']['accepted']['total_cpu_ns']['sum_known_ns'], 170)
        self.assertEqual(values['by_dispatch_outcome']['unknown']['total_cpu_ns']['unknown_count'], 1)
        self.assertFalse(values['scope']['total_is_whole_request_cpu'])
        self.assertFalse(values['scope']['cpu_settle_phase_is_additive_to_original_total'])
        self.assertFalse(values['scope']['includes_settlement_tail_after_original_owner_sample'])
        self.assertEqual(result['request_owner_completion']['records_without_lifecycle'], 5)
        self.assertNotIn('original_cpu_samples', reader.cpu_settlement_summary([settlement_record()]))
        self.assertNotIn('request_owner_completion', reader.execution_summary(
            [settlement_record()], True, observer_v4=True))

    def test_original_settlement_values_refuse_missing_negative_overflow_bool_and_forged_sums(self):
        mutations = [
            lambda r: r['cpu_settlement'].update(schema=reader.CPU_SETTLEMENT_SCHEMA),
            lambda r: r['cpu_settlement'].update(owner_cpu_known=False),
            lambda r: r['cpu_settlement'].update(total_cpu_ns=100),
            lambda r: r['cpu_settlement'].update(total_cpu_ns=171),
            lambda r: r['cpu_settlement'].update(live_paid_cpu_ns=170),
            lambda r: r['cpu_settlement'].update(residual_cpu_ns=170),
            lambda r: r['cpu_settlement'].update(scoped_worker_cpu_ns=None),
            lambda r: r['cpu_settlement'].update(total_cpu_ns=None),
            lambda r: r['cpu_settlement'].update(owner_cpu_ns=(1 << 64)-1, scoped_worker_cpu_ns=1,
                                                total_cpu_ns=0, live_paid_cpu_ns=0, residual_cpu_ns=0),
        ]
        for key in reader.CPU_SETTLEMENT_VALUE_FIELDS:
            mutations.append(lambda r, key=key: r['cpu_settlement'].pop(key))
            for invalid in (True, -1, 1 << 64, '100', 1.5):
                mutations.append(lambda r, key=key, invalid=invalid: r['cpu_settlement'].update({key: invalid}))
        for index, mutate in enumerate(mutations):
            row = settlement_values_record()
            mutate(row)
            with self.subTest(index=index), self.assertRaises(ValueError):
                reader.execution_summary([row], True, observer_v4=True)

    def test_unknown_original_total_is_not_reconstructed_from_readable_component_clocks(self):
        row = settlement_values_record()
        row['cpu_settlement'].update(total_cpu_ns=None, residual_cpu_ns=None,
            residual_cpu_known=False, budget_settled=False)
        row['submit_phases'][reader.PHASES_V4.index('cpu_settle')]['accepted'] = False
        value = reader.execution_summary([row], True, observer_v4=True)['cpu_settlement']['original_cpu_samples']
        self.assertEqual(value['values_ns']['owner_cpu_ns']['sum_known_ns'], 100)
        self.assertEqual(value['values_ns']['scoped_worker_cpu_ns']['sum_known_ns'], 70)
        self.assertEqual(value['values_ns']['total_cpu_ns']['unknown_count'], 1)
        self.assertEqual(value['values_ns']['total_cpu_ns']['known_count'], 0)

    def test_v2_original_residual_cannot_be_missing_with_known_nonnegative_subtraction(self):
        row = settlement_values_record()
        row['cpu_settlement'].update(residual_cpu_ns=None, residual_cpu_known=False,
                                     budget_settled=False)
        row['submit_phases'][reader.PHASES_V4.index('cpu_settle')]['accepted'] = False
        with self.assertRaisesRegex(ValueError, 'paid plus residual mismatch'):
            reader.execution_summary([row], True, observer_v4=True)
        # The actual native checked subtraction can fail on underflow. Keep
        # both readable original samples and the unknown residual, without
        # turning their difference into a negative cost or a successful debit.
        row['cpu_settlement']['live_paid_cpu_ns'] = 180
        value = reader.execution_summary([row], True, observer_v4=True)['cpu_settlement']
        self.assertEqual(value['budget_not_settled'], 1)
        samples = value['original_cpu_samples']['values_ns']
        self.assertEqual(samples['total_cpu_ns']['sum_known_ns'], 170)
        self.assertEqual(samples['live_paid_cpu_ns']['sum_known_ns'], 180)
        self.assertEqual(samples['residual_cpu_ns']['unknown_count'], 1)

    def test_v2_budget_success_requires_a_known_original_residual(self):
        for unavailable in ('total', 'live_paid', 'underflow'):
            row = settlement_values_record()
            value = row['cpu_settlement']
            value.update(residual_cpu_ns=None, residual_cpu_known=False)
            if unavailable == 'total':
                value['total_cpu_ns'] = None
            elif unavailable == 'live_paid':
                value.update(live_paid_cpu_ns=None, live_paid_cpu_known=False)
            else:
                value['live_paid_cpu_ns'] = 180
            row['submit_phases'][reader.PHASES_V4.index('cpu_settle')]['accepted'] = False
            with self.subTest(unavailable=unavailable), self.assertRaisesRegex(
                    ValueError, 'successful budget requires original residual'):
                reader.execution_summary([row], True, observer_v4=True)
        # V1 has no original numeric operands. Its historical validation and
        # derivation stay unchanged; the v2 invariant is not backfilled into it.
        old = settlement_record(residual_cpu_known=False)
        value = reader.execution_summary([old], True, observer_v4=True)['cpu_settlement']
        self.assertEqual((value['budget_settled'], value['failed']), (1, 1))
        self.assertNotIn('original_cpu_samples', value)

    def test_request_owner_clocks_keep_post_disconnect_tail_and_unfinished_costs(self):
        late = lifecycle_record()
        early = lifecycle_record(connection=90, task=40)
        open_task = lifecycle_record(task=None)
        refused = lifecycle_record(task=None, created=False)
        del refused['cpu_settlement']
        unreadable = lifecycle_record(accepted=None, failed=True)
        legacy = settlement_record()
        rows = [late, early, open_task, refused, unreadable, legacy]
        before = copy.deepcopy(rows)
        value = reader.execution_summary(rows, True, observer_v4=True)['request_owner_completion']
        self.assertEqual(rows, before)
        self.assertEqual((value['retained_records'], value['records_with_lifecycle'],
                          value['records_without_lifecycle'], value['owners_closed_records'],
                          value['connection_closed_task_still_open'], value['no_task_created_records']),
                         (6, 5, 1, 4, 1, 1))
        lifetime = value['accept_to_all_owners_closed_wall_ns']
        self.assertEqual((lifetime['known_count'], lifetime['unknown_count'], lifetime['sum_known_ns']), (3, 3, 190))
        tail = value['task_ownership_after_connection_close_wall_ns']
        self.assertEqual((tail['known_count'], tail['unknown_count'], tail['sum_known_ns']), (3, 1, 100))
        cost = value['original_total_cpu_for_completed_post_disconnect_owners_ns']
        self.assertEqual((cost['known_count'], cost['sum_known_ns']), (2, 340))
        self.assertFalse(value['scope']['post_disconnect_tail_is_cpu_cost'])
        self.assertFalse(value['scope']['cancellation_signal_time_measured'])
        self.assertIsNone(value['scope']['whole_request_population_p99_ns'])
        self.assertIsNone(value['scope']['business_tps_capacity'])
        self.assertEqual(reader.request_owner_lifecycle_summary([])['owners_closed_records'], 0)
        # An old source with lifecycle clocks but no v2 values must reproduce
        # the same historical derivation, rather than acquire new fields.
        old = copy.deepcopy(late)
        old['cpu_settlement'] = settlement_record()['cpu_settlement']
        self.assertNotIn('request_owner_completion', reader.execution_summary([old], True, observer_v4=True))

    def test_request_owner_clocks_reject_early_terminal_and_invalid_unknown_claims(self):
        mutations = [
            lambda r: r['lifecycle'].update(schema='unknown'),
            lambda r: r['lifecycle'].update(has_control_authority=True),
            lambda r: r['lifecycle'].update(clock_is_observer_local=False),
            lambda r: r['lifecycle'].update(accepted_ns=None),
            lambda r: r['lifecycle'].update(connection_closed_ns=None),
            lambda r: r['lifecycle'].update(task_closed_ns=None),
            lambda r: r['lifecycle'].update(connection_closed_ns=9),
            lambda r: r['lifecycle'].update(task_closed_ns=9),
            lambda r: r['lifecycle'].update(extra=True),
            lambda r: r.update(connection_closed=False),
            lambda r: r.update(task_created=False),
            lambda r: r.update(task_closed=False),
            lambda r: r.update(complete=False),
            lambda r: r.update(observation_failed=True),
            lambda r: r.pop('task_created'),
        ]
        for key in ('accepted_ns', 'connection_closed_ns', 'task_closed_ns'):
            for invalid in (True, -1, 1 << 64, '100'):
                mutations.append(lambda r, key=key, invalid=invalid: r['lifecycle'].update({key: invalid}))
        for index, mutate in enumerate(mutations):
            row = lifecycle_record()
            mutate(row)
            with self.subTest(index=index), self.assertRaises(ValueError):
                reader.execution_summary([row], True, observer_v4=True)

    def test_client_history_import_readback_keeps_failure_unknowns_and_legacy_denominators(self):
        row = observed_history_call()
        row['client_import'].update(thread_cpu_ns=None, thread_cpu_observation_available=False)
        row['client_import']['native_import_observation']['host_checks'][2].update(
            thread_cpu_ns=None, cpu_clock_unknown_calls=1)
        legacy = copy.deepcopy(row)
        del legacy['client_import']['native_import_observation']
        self.assertIsNone(reader.client_history_import_observations([legacy]))
        old_phase = reader.phase_summary(attribution_phase([], [legacy], [], []))
        self.assertNotIn('client_history_import_observations', old_phase)
        calls = [row, legacy, attribution_call('bc' * 32)]
        before = copy.deepcopy(calls)
        phase = reader.phase_summary(attribution_phase([], calls, [], []))
        value = phase['client_history_import_observations']
        self.assertEqual(calls, before)
        self.assertEqual((value['history_calls'], value['retained_client_imports'],
                          value['observed_imports'], value['legacy_imports_without_observation'],
                          value['history_calls_without_import_stage']), (3, 2, 1, 1, 1))
        self.assertEqual(value['observed_outcomes'], {'rejected': 1})
        retained = value['records'][0]['client_import']
        self.assertIsNone(retained['thread_cpu_ns'])
        self.assertIsNone(retained['native_import_observation']['host_checks'][2]['thread_cpu_ns'])
        self.assertEqual(retained['error'], 'PUBLIC_REQUEST_DEADLINE')
        self.assertNotIn('total_cpu_ns', value)
        self.assertTrue(value['scope']['nested_intervals_are_not_additive'])
        self.assertFalse(value['scope']['host_cpu_is_full_worker_cpu'])
        self.assertIsNone(value['scope']['business_tps_capacity'])
        self.assertEqual(phase['confirmed_rounds'], 0)

    def test_client_history_import_rejects_bad_shapes_clocks_and_missing_host_data(self):
        mutations = [
            lambda r: r['client_import'].pop('thread_cpu_ns'),
            lambda r: r['client_import'].update(thread_cpu_ns=float('nan')),
            lambda r: r['client_import'].update(thread_cpu_observation_available=False),
            lambda r: r['client_import'].update(ended_ns=999),
            lambda r: r['client_import'].update(error=None),
            lambda r: r['client_import'].update(scope='all workers CPU'),
            lambda r: r.update(status='refused'),
            lambda r: r.update(returned_after_window=True),
            lambda r: r['client_import'].update(native_import_observation=None),
            lambda r: r['client_import']['native_import_observation'].pop('host_checks'),
            lambda r: r['client_import']['native_import_observation']['host_checks'][2].update(calls_started=3),
            lambda r: r['client_import']['native_import_observation']['host_checks'][2].update(first_started_ns=9),
        ]
        for index, mutate in enumerate(mutations):
            row = observed_history_call()
            mutate(row)
            with self.subTest(index=index), self.assertRaises(ValueError):
                reader.client_history_import_observations([row])

    def test_client_history_import_binds_actual_request_and_supplied_count(self):
        for index, mutate in enumerate((
            lambda r: r['request'].update(op='head'),
            lambda r: r['request'].update(tip='ff' * 32),
            lambda r: r['request'].update(after='ff' * 32),
            lambda r: r['response']['value'].update(packets=[]),
            lambda r: r['client_import'].update(succeeded=True, error=None),
        )):
            row = observed_history_call()
            mutate(row)
            with self.subTest(index=index), self.assertRaises(ValueError):
                reader.client_history_import_observations([row])
        row = observed_history_call()
        with self.assertRaisesRegex(ValueError, 'bounded client History'):
            reader.client_history_import_observations([row] * 65)

    def test_client_history_import_preserves_native_success_followed_by_final_host_refusal(self):
        row = observed_history_call()
        native = row['client_import']['native_import_observation']
        for slots in [native['phases'], *(p['phases'] for p in native['packets'])]:
            for phase in slots:
                if phase['completed']:
                    phase.update(accepted=True, error_code=None)
        native['host_checks'][2].update(calls_accepted=2, calls_rejected=0, last_error_code=None)
        row['client_import'].update(succeeded=True, error=None)
        value = reader.client_history_import_observations([row])
        self.assertEqual(value['observed_outcomes'], {'accepted': 1})
        native['host_checks'][3].update(calls_accepted=0, calls_rejected=1,
                                       last_error_code='PUBLIC_HOST_KERNEL_CONTEXT')
        row['client_import'].update(succeeded=False, error='PUBLIC_HOST_KERNEL_CONTEXT')
        value = reader.client_history_import_observations([row])
        self.assertEqual(value['observed_outcomes'], {'rejected': 1})
        retained = value['records'][0]['client_import']['native_import_observation']
        self.assertTrue(retained['phases'][reader.PHASES_V4.index('history_import')]['accepted'])
        self.assertEqual(retained['host_checks'][3]['calls_rejected'], 1)

    def test_v4_nested_failed_and_cancelled_intervals_are_separate(self):
        row = record_v4()
        for name, start, end, cpu in [('admission', 10, 110, 30), ('execution', 20, 90, 22),
                                      ('root_commitment', 50, 90, 12)]:
            phase = row['submit_phases'][reader.PHASES_V4.index(name)]
            phase.update(started=True, completed=True, accepted=False, error_code='PUBLIC_REQUEST_CANCELLED',
                         started_ns=start, ended_ns=end, wall_ns=end-start, thread_cpu_ns=cpu)
        row['paid_task_queue_wait'].update(started_ns=0, ended_ns=10, wall_ns=10,
                                           completed=True, accepted=True)
        value = reader.execution_summary([row], True, observer_v4=True)
        self.assertNotIn('total_cpu_ns', value)
        root = value['submit_phases'][-1]
        self.assertEqual(root['parent_phase'], 'execution')
        self.assertEqual(root['thread_cpu_ns']['sum_known_ns'], 12)
        self.assertEqual(root['error_code_counts'], {'PUBLIC_REQUEST_CANCELLED': 1})
        self.assertEqual(value['wait_intervals']['grant_wait']['wall_ns']['known_count'], 0)
        root = row['submit_phases'][-1]
        root.update(started_ns=19, ended_ns=90, wall_ns=71)
        with self.assertRaisesRegex(ValueError, 'escapes its inclusive parent'):
            reader.execution_summary([row], True, observer_v4=True)
        # Missing/unfinished parent clocks are not replaced by invented bounds.
        parent = row['submit_phases'][reader.PHASES_V4.index('execution')]
        parent.update(started_ns=None)
        reader.execution_summary([row], True, observer_v4=True)

    def test_v4_rejects_missing_nonfinite_and_inconsistent_slots(self):
        import copy
        row = record_v4()
        cases = []
        wrong = copy.deepcopy(row); wrong['submit_phases'].pop(); cases.append(wrong)
        wrong = copy.deepcopy(row); del wrong['submit_phases'][0]['started_ns']; cases.append(wrong)
        wrong = copy.deepcopy(row); wrong['submit_phases'][0]['wall_ns'] = float('nan'); cases.append(wrong)
        wrong = copy.deepcopy(row); wrong['submit_phases'][0]['wall_ns'] = 0; cases.append(wrong)
        wrong = copy.deepcopy(row); wrong['submit_phases'][-1]['parent_phase'] = 'admission'; cases.append(wrong)
        wrong = copy.deepcopy(row); del wrong['paid_task_queue_wait']; cases.append(wrong)
        wrong = copy.deepcopy(row); wrong['grant_wait'].update(completed=True, accepted=True); cases.append(wrong)
        wrong = copy.deepcopy(row); wrong['grant_wait'].update(started_ns=2, ended_ns=1, wall_ns=0); cases.append(wrong)
        wrong = copy.deepcopy(row); wrong['terminal_error_code'] = 'unbounded remote text'; cases.append(wrong)
        for index, wrong in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValueError):
                reader.execution_summary([wrong], True, observer_v4=True)

    def test_v4_scope_is_explicit_and_does_not_relabel_v3(self):
        phase = attribution_phase([], [], [], [record_v4()])
        phase['receiver_observation'].update(
            schema='public-v3-local-request-resource-observation-v4',
            cpu_includes_reactor_authentication_or_response_signing=True,
            cpu_includes_reactor_authentication=False, dispatch_cpu_includes_paid_body_decode=True,
            dispatch_cpu_includes_response_signing=True, phase_parent_links_are_inclusive=True,
            cpu_wait_is_outside_dispatch=True, monotonic_epoch_is_observer_local=True)
        summary = reader.phase_summary(phase)
        self.assertEqual(len(summary['receiver']['all_retained_records']['submit_phases']), 19)
        phase['receiver_observation']['schema'] = 'public-v3-local-request-resource-observation-v3'
        with self.assertRaisesRegex(ValueError, 'seven ordered'):
            reader.phase_summary(phase)

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

    def test_r16_policy_preserves_failures_and_cannot_relabel_r14_phases(self):
        # Synthetic reader controls only. A new profile is not new native evidence.
        for arithmetic in (False, True):
            with self.subTest(arithmetic=arithmetic):
                report = arithmetic_report()
                policy = arithmetic_policy if arithmetic else observation
                if not arithmetic:
                    report['schema'] = 'native-public-v3-separate-process-campaign-v2'
                    del report['work_profile']
                    for phase in report['phases']:
                        del phase['work_profile']
                        del phase['work_arithmetic_owner']
                        for row in phase['receiver_observation']['records']:
                            row.pop('work_arithmetic', None)
                report['public_resource_policy'] = policy('r14')
                for phase in report['phases']:
                    phase['public_resource_policy'] = policy('r14')
                historical = copy.deepcopy(report)
                historical_result = reader.analyze(historical)
                expected_historical = 'r14-arithmetic-facts-v1' if arithmetic else 'r14'
                self.assertEqual([p['public_resource_policy']['resource_revision']
                                  for p in historical_result['phases']], [expected_historical] * 3)
                if arithmetic:
                    self.assertEqual(historical_result['public_resource_policy']['resource_revision'],
                                     expected_historical)
                report['public_resource_policy'] = policy('r16')
                with self.assertRaisesRegex(ValueError, 'mixed or missing phase resource policies'):
                    reader.analyze(report)
                for phase in report['phases']:
                    phase['public_resource_policy'] = policy('r16')
                result = reader.analyze(report)
                expected_current = 'r16-arithmetic-facts-v1' if arithmetic else 'r16'
                if arithmetic:
                    self.assertEqual(result['public_resource_policy']['resource_revision'],
                                     expected_current)
                self.assertEqual([p['public_resource_policy']['resource_revision']
                                  for p in result['phases']], [expected_current] * 3)
                self.assertEqual([p['confirmed_rounds'] for p in result['phases']], [0, 0, 0])
                self.assertFalse(result['native_finite_experiment_criteria_met'])
                self.assertFalse(result['scope']['production_qualification'])
                self.assertIsNone(result['honest_preparation_cpu_ns'])
                self.assertEqual(reader.analyze(historical), historical_result)
                wrong_scope = copy.deepcopy(report)
                wrong_scope['phases'][0]['receiver_observation']['schema'] = \
                    'public-v3-local-request-resource-observation-v2'
                with self.assertRaisesRegex(ValueError, 'policy and observed CPU scope disagree'):
                    reader.analyze(wrong_scope)
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
        for unknown in (None, 'pon-public-v3-multiprocess-phase-derivation-v4'):
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

    def test_duplicate_nested_observation_cannot_overwrite_failure_or_missing_duration(self):
        # A correct byte hash cannot make an ambiguous document authoritative.
        # Each input below is otherwise a full reader-valid synthetic campaign.
        phases = [attribution_phase([], [], [], [record()]) for _ in reader.MODES]
        for phase, mode in zip(phases, reader.MODES):
            phase['mode'] = mode
            phase['receiver_observation']['records'][0]['submit_phases'][0].update(
                started=True, completed=True, accepted=False, wall_ns=None)
        report = dict(schema='native-public-v3-separate-process-campaign-v2',
            state_backend='authenticated-v1', finite_experiment_criteria_met=False,
            economics_complete=False, best_observed_cold_legal_method=None,
            preparation=dict(cpu_ns=None, wall_ns=None), phases=phases)
        original = json.dumps(report).encode()
        reader.analyze(report)
        for old, new in (
            (b'"dispatch_accepted": false', b'"dispatch_accepted": false, "dispatch_accepted": true'),
            (b'"accepted": false, "wall_ns": null',
             b'"accepted": false, "wall_ns": null, "wall_ns": 0'),
            (b'"dispatch_accepted": false', b'"dispatch_accepted": false, "dispatch_accep\\u0074ed": true'),
        ):
            raw = original.replace(old, new, 1)
            self.assertNotEqual(raw, original)
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'report.json'
                path.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, 'duplicate JSON observation key'):
                    reader.read_report(path, hashlib.sha256(raw).hexdigest())
                self.assertEqual(path.read_bytes(), raw)

    def test_report_descriptor_bounds_exact_limit_and_overflow(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(reader, 'MAX_REPORT_BYTES', 8):
            path = Path(directory) / 'report.json'
            for size in (0, 1, 7, 8):
                path.write_bytes(b'x' * size)
                self.assertEqual(reader.read_report_bytes(path), b'x' * size)
            path.write_bytes(b'x' * 9)
            with self.assertRaisesRegex(ValueError, 'finite reader byte limit'):
                reader.read_report_bytes(path)

    def test_report_short_reads_continue_to_eof(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(reader, 'MAX_REPORT_BYTES', 8):
            path = Path(directory) / 'report.json'
            path.write_bytes(b'12345678')
            original = os.read
            def short(descriptor, size):
                return original(descriptor, min(size, 3))
            with patch.object(reader.os, 'read', side_effect=short):
                self.assertEqual(reader.read_report_bytes(path), b'12345678')

    def test_report_growth_after_descriptor_stat_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(reader, 'MAX_REPORT_BYTES', 8):
            path = Path(directory) / 'report.json'
            path.write_bytes(b'x' * 8)
            original = os.fstat
            def grow(descriptor):
                before = original(descriptor)
                with path.open('ab') as stream:
                    stream.write(b'y' * 65536)
                return before
            original_read = os.read
            requests, descriptors, offsets = [], [], []
            def observed_read(descriptor, size):
                requests.append(size)
                descriptors.append(descriptor)
                self.assertLessEqual(size, 9)
                chunk = original_read(descriptor, size)
                offsets.append(os.lseek(descriptor, 0, os.SEEK_CUR))
                return chunk
            with patch.object(reader.os, 'fstat', side_effect=grow), \
                    patch.object(reader.os, 'read', side_effect=observed_read):
                with self.assertRaisesRegex(ValueError, 'finite reader byte limit'):
                    reader.read_report_bytes(path)
            self.assertEqual(requests, [9])
            self.assertEqual(offsets, [9])
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    original(descriptor)

    def test_report_path_replacement_does_not_switch_open_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_bytes(b'original')
            replacement = Path(directory) / 'replacement'
            replacement.write_bytes(b'changed')
            original = os.fstat
            def replace(descriptor):
                before = original(descriptor)
                replacement.replace(path)
                return before
            with patch.object(reader.os, 'fstat', side_effect=replace):
                self.assertEqual(reader.read_report_bytes(path), b'original')
            self.assertEqual(path.read_bytes(), b'changed')

    def test_report_symlink_directory_and_fifo_are_refused_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'
            target.write_bytes(b'{}')
            link = root / 'link'
            link.symlink_to(target)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            original = os.open
            opened = []
            def checked_open(path, flags):
                # Fail before opening if a mutant removes nonblocking/no-follow.
                self.assertTrue(flags & os.O_NONBLOCK)
                self.assertTrue(flags & os.O_NOFOLLOW)
                descriptor = original(path, flags)
                opened.append(descriptor)
                return descriptor
            with patch.object(reader.os, 'open', side_effect=checked_open):
                for path in (link, root, fifo):
                    with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                        reader.read_report_bytes(path)
            for descriptor in opened:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            self.assertEqual(target.read_bytes(), b'{}')

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
