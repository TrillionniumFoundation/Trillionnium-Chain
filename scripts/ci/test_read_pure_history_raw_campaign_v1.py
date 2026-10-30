#!/usr/bin/env python3
"""Synthetic reader rejection controls; these are never native campaign evidence."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import read_pure_history_raw_campaign_v1 as reader
import test_native_history_verifier as native_fixture


def call(status='refused'):
    return {
        'work_profile': reader.WORK_PROFILE,
        'public_resource_policy': copy.deepcopy(reader.expected_policy()),
        'pure_history_acknowledgement': {
            'schema': 'public-pure-history-raw-acknowledgement-v1',
            'profile': reader.PROFILE, 'policy_id': reader.POLICY_ID,
            'ticket_bits': 0, 'search_budget': 0, 'solution_trials': 0, 'solution_nonce': 0,
        },
        'metrics': {'solution_found': True, 'solution_trials': 0, 'solution_search_ns': 0},
        'status': status, 'response': {'solve_trials': 0},
    }


def sample(depleted=False):
    debit = 1_950_000_000 if depleted else 250_000_000
    refill = 0 if depleted else 250_000_000
    credit = 2_000_000_000 + refill - debit
    return {'meter': {'Ok': {
        'depleted': depleted, 'clock_failures': 0,
        'meter': {'burst_ns': 2_000_000_000, 'refill_ns_per_second': 250_000_000,
                  'start_reserve_ns': 100_000_000, 'worker_limit': 2,
                  'in_flight': 0, 'accounting_unavailable': False},
        'actual_flow': {
            'balance_identity_verified': True, 'initial_credit_ns': 2_000_000_000,
            'credited_refill_ns': refill, 'paid_cpu_debit_ns': debit,
            'settlement_discard_ns': 0, 'remaining_paid_credit_ns': credit,
            'stored_credit_ns': credit, 'booked_reservation_ns': 0,
            'live_debited_cpu_ns': 0, 'settlement_residual_cpu_ns': debit,
            'settled_full_cpu_ns': debit,
            'live_owners': 0, 'unsettled_known_live_cpu_ns': 0,
        },
    }}}


def live_sample(remaining=50_000_000, owners=1, live=50_000_000):
    value = sample(True)
    flow = value['meter']['Ok']['actual_flow']
    paid = 2_000_000_000 - remaining
    flow.update(remaining_paid_credit_ns=remaining, paid_cpu_debit_ns=paid,
                stored_credit_ns=remaining - owners * 100_000_000,
                booked_reservation_ns=owners * 100_000_000, live_owners=owners,
                live_debited_cpu_ns=live, settlement_residual_cpu_ns=paid - live,
                settled_full_cpu_ns=paid - live, unsettled_known_live_cpu_ns=live)
    value['meter']['Ok']['meter']['in_flight'] = owners
    value['meter']['Ok']['depleted'] = remaining < 100_000_000 and paid > 1_900_000_000
    return value


def completion():
    return {
        'schema': 'public-v3-live-owner-completion-work-v1',
        'identity_domain': 'public-v3-complete-work-identity-v1',
        'identity_capacity': 4096, 'identity_storage_bytes': 4096 * 32,
        'epoch_scope': 'same-shared-live-cpu-owner',
        'evicts_live_epoch_identities': False, 'survives_process_restart': False,
        'full_capacity_disables_ordinary_verification': False,
        'retained_identities': 21, 'live_completions': 0,
        'repeated_identity_skips': 0, 'full_capacity_skips': 0,
    }


def observation():
    records = []
    for accepted in [True] * 21 + [False]:
        records.append({
            'full_work_accepted': accepted,
            'submit_phases': [{'phase': name, 'started': False} for name in
                              ('decode', 'context_owner_wait', 'context', 'work',
                               'admission_owner_wait', 'admission', 'submit_result')],
        })
    return {
        'schema': 'public-v3-local-request-resource-observation-v3', 'records': records,
        'cpu_intervals_are_nested_not_additive': True,
        'cpu_includes_reactor_authentication_or_response_signing': True,
        'cpu_includes_reactor_authentication': False,
        'dispatch_cpu_includes_paid_body_decode': True,
        'dispatch_cpu_includes_response_signing': True,
        'submit_phase_cpu_excludes_scoped_workers': True,
    }


def enrich_phase(phase, passed=False):
    attack = phase['mode'] != 'baseline'
    phase.update({
        'public_resource_policy': copy.deepcopy(reader.expected_policy()),
        'work_profile': reader.WORK_PROFILE, 'duration_seconds': 30,
        'attacker_processes_requested': 24 if attack else 0,
        'attacker_processes_ready': 24 if attack else 0,
        'submissions': [call('ok')],
        'children': [{'report': {'result': {
            'work_profile': reader.WORK_PROFILE,
            'public_resource_policy': copy.deepcopy(reader.expected_policy()),
            'calls': [call()],
        }}} for _ in range(24 if attack else 0)],
        'pure_history_acknowledgements_verified': True,
        'budget_samples': [sample(passed and attack)],
        'genuine_budget_depletion_observed': passed and attack,
        'final_actual_flow': sample()['meter']['Ok']['actual_flow'],
        'final_meter': sample()['meter']['Ok']['meter'],
        'completion_work_observation': completion(),
        'receiver_observation': observation(),
        'all_signed_rounds_confirmed_in_window': passed,
        'finite_phase_criteria_met': passed, 'observer_complete': True,
        'verifier_errors': [], 'service_outcome': {'Ok': {'mutation_cpu_clock_failures': 0}},
        'actor_reports_successful_without_cap_or_kill': True,
        'full_work_failed': 1, 'full_work_accepted': 21,
        'attack_calls_overlapping_each_signed_round': [24, 24, 24],
    })
    for row in phase['history']:
        fields = call('ok')
        fields['response'].update(row['response'])
        row.update(fields)
    for index, row in enumerate(phase['confirmations']):
        row.update({'round': index, 'ended_ns': (index + 1) * 1_000_000_000,
                    'confirmed_inside_pressure_window': passed,
                    'paid_credit_depletion_observed_during_round': passed and attack,
                    'receiver_hostile_work_rejected_during_round': passed and attack})
        if passed:
            row['observation'] = {'confirmed': True, 'finalized': False,
                                  'execution_authority': False, 'depth': 6}


def fixture(root):
    report, ipc = native_fixture.fixture(root)
    report.update({
        'schema': reader.SCHEMA, 'work_profile': reader.WORK_PROFILE,
        'public_resource_policy': copy.deepcopy(reader.expected_policy()),
        'state_backend': 'authenticated-v1', 'economics_complete': True,
        'finite_experiment_criteria_met': False,
        'preparation': {'actual_signed_seed_transfers': 1024, 'seed_blocks': 4,
                        'business_blocks': 21},
    })
    for phase in report['phases']:
        enrich_phase(phase)
    return report, ipc


class PureHistoryReader(unittest.TestCase):
    def read(self, root, report):
        path = root / 'report.json'
        digest = native_fixture.put(path, report)
        return reader.read_report(path, digest, reader.POLICY_ID, native_fixture.BINARY,
                                  native_fixture.OUTER, reader.history_reader.STRICT_PROFILE)

    def test_independent_fixed_signed_policy_vector(self):
        self.assertEqual(reader.expected_policy()['policy_id'],
                         'bf409dae237253a2ce14152c54198ed06e824e709763946e9c84e68e894eee58')
        self.assertEqual(reader.expected_policy()['ticket_bits'], 0)

    def test_complete_synthetic_boundary_retains_original_red(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report, _ = fixture(root)
            result = self.read(root, report)
            self.assertTrue(result['native_history']['complete'])
            self.assertFalse(result['original_criteria_met'])
            self.assertFalse(result['production_qualified'])
            self.assertEqual([p['actual_zero_search_calls'] for p in result['phases']], [2, 26, 26])

    def test_pure_calls_reject_nonzero_missing_and_foreign_receipts(self):
        reader.admission_call(call())
        for section, key, value in [
            ('pure_history_acknowledgement', 'ticket_bits', 8),
            ('pure_history_acknowledgement', 'search_budget', 1_048_576),
            ('pure_history_acknowledgement', 'solution_trials', 1),
            ('pure_history_acknowledgement', 'solution_nonce', 1),
            ('pure_history_acknowledgement', 'solution_nonce', False),
            ('pure_history_acknowledgement', 'profile', 'public-protected-development-v3'),
            ('pure_history_acknowledgement', 'policy_id', '00' * 32),
            ('metrics', 'solution_trials', 1), ('metrics', 'solution_search_ns', 1),
            ('metrics', 'solution_found', None), ('response', 'solve_trials', 1),
            ('public_resource_policy', 'ticket_bits', 8),
            ('public_resource_policy', 'ticket_bits', False),
            ('public_resource_policy', 'ticket_bits', 0.0),
            ('public_resource_policy', 'lifetime_ms', 2000.0),
        ]:
            with self.subTest(section=section, key=key, value=value):
                altered = call()
                altered[section][key] = value
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    reader.admission_call(altered)
        altered = call()
        del altered['pure_history_acknowledgement']
        with self.assertRaises(KeyError):
            reader.admission_call(altered)

    def test_unreached_acknowledgement_keeps_unknown_nonce(self):
        row = call('error')
        row['metrics']['solution_found'] = False
        row['pure_history_acknowledgement']['solution_nonce'] = None
        reader.admission_call(row)
        row['pure_history_acknowledgement']['solution_nonce'] = 0
        with self.assertRaises(ValueError):
            reader.admission_call(row)

    def test_protected_top_level_phase_actor_and_call_cannot_be_relabelled(self):
        for location in ('schema', 'policy', 'phase', 'actor', 'call'):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                report, _ = fixture(root)
                if location == 'schema':
                    report['schema'] = 'native-public-v3-separate-process-campaign-v2'
                elif location == 'policy':
                    report['public_resource_policy']['ticket_bits'] = 8
                elif location == 'phase':
                    report['phases'][0]['work_profile'] = 'arithmetic-facts-v1'
                elif location == 'actor':
                    report['phases'][1]['children'][0]['report']['result']['work_profile'] = 'raw-r13'
                else:
                    report['phases'][1]['children'][0]['report']['result']['calls'][0]['metrics']['solution_trials'] = 7
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    self.read(root, report)

    def test_actual_independent_verifier_and_lifeline_are_mandatory(self):
        for change in ('incomplete', 'forced_kill', 'fixed_limit', 'node_close',
                       'lifeline_not_armed', 'lifeline_early_disarm', 'after_tasks'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                report, ipc = fixture(root)
                native_fixture.boundary_change(change, report['phases'][0], ipc[0])
                native_fixture.flush(report, ipc)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    self.read(root, report)

    def test_original_phase_gates_and_full_w1_shape_remain_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            report, _ = fixture(Path(temporary))
            phase = report['phases'][1]
            enrich_phase(phase, passed=True)
            self.assertTrue(reader.phase_bindings(phase)['original_phase_criteria_met'])
            for key, value in [
                ('receiver_client_state_equal', False), ('duration_seconds', 31),
                ('observer_complete', False), ('attacker_processes_ready', 23),
                ('actor_reports_successful_without_cap_or_kill', False),
                ('full_work_failed', 0), ('full_work_accepted', 20),
                ('attack_calls_overlapping_each_signed_round', [24, 0, 24]),
                ('work_arithmetic_owner', {'slots': 64}),
            ]:
                with self.subTest(key=key):
                    altered = copy.deepcopy(phase)
                    altered[key] = value
                    with self.assertRaises((ValueError, KeyError, TypeError)):
                        reader.phase_bindings(altered)
            for change in ('late', 'authority', 'depth_float', 'depletion', 'settlement', 'clock', 'accepted_attack', 'cache'):
                with self.subTest(change=change):
                    altered = copy.deepcopy(phase)
                    if change == 'late': altered['confirmations'][2]['ended_ns'] = 30_000_000_000
                    elif change == 'authority': altered['confirmations'][0]['observation']['execution_authority'] = True
                    elif change == 'depth_float': altered['confirmations'][0]['observation']['depth'] = 6.0
                    elif change == 'depletion':
                        altered['budget_samples'] = [sample()]
                        altered['genuine_budget_depletion_observed'] = False
                    elif change == 'settlement': altered['final_actual_flow']['live_owners'] = 1
                    elif change == 'clock': altered['service_outcome']['Ok']['mutation_cpu_clock_failures'] = 1
                    elif change == 'accepted_attack': altered['children'][0]['report']['result']['calls'][0]['status'] = 'ok'
                    else: altered['receiver_observation']['records'][0]['work_arithmetic'] = {}
                    with self.assertRaises((ValueError, KeyError, TypeError)):
                        reader.phase_bindings(altered)
            for key in ('duration_seconds', 'attacker_processes_requested', 'attacker_processes_ready',
                        'full_work_failed', 'full_work_accepted'):
                for invalid in (False, float(phase[key]), -1):
                    with self.subTest(typed_phase_counter=key, invalid=invalid):
                        altered = copy.deepcopy(phase)
                        altered[key] = invalid
                        with self.assertRaises(ValueError):
                            reader.phase_bindings(altered)

    def test_depletion_requires_original_budget_and_actual_cpu_conservation(self):
        self.assertFalse(reader.actual_depletion(sample()))
        self.assertTrue(reader.actual_depletion(sample(True)))
        for key, value in [('burst_ns', 1_000_000_000), ('refill_ns_per_second', 0),
                           ('worker_limit', 3), ('start_reserve_ns', 200_000_000)]:
            altered = sample(True)
            altered['meter']['Ok']['meter'][key] = value
            with self.assertRaises(ValueError):
                reader.actual_depletion(altered)
        altered = sample(True)
        altered['meter']['Ok']['actual_flow']['paid_cpu_debit_ns'] -= 1
        with self.assertRaises(ValueError):
            reader.actual_depletion(altered)
        # Python booleans compare equal to 0/1, and floats can satisfy the same
        # identities. Neither is an actual Rust integer accounting observation.
        flow_keys = tuple(key for key in sample()['meter']['Ok']['actual_flow']
                          if key != 'balance_identity_verified')
        meter_keys = ('burst_ns', 'refill_ns_per_second', 'start_reserve_ns', 'worker_limit', 'in_flight')
        for section, keys in [('actual_flow', flow_keys), ('meter', meter_keys)]:
            for key in keys:
                for invalid in (False, 0.0, -1):
                    with self.subTest(section=section, key=key, invalid=invalid):
                        altered = sample(True)
                        altered['meter']['Ok'][section][key] = invalid
                        with self.assertRaises(ValueError):
                            reader.actual_depletion(altered)
        for invalid in (False, 0.0, -1):
            altered = sample(True)
            altered['meter']['Ok']['clock_failures'] = invalid
            with self.assertRaises(ValueError):
                reader.actual_depletion(altered)
        # Reproduce the independently found balanced-but-negative depletion.
        altered = sample(True)
        flow = altered['meter']['Ok']['actual_flow']
        flow['paid_cpu_debit_ns'] = flow['settlement_residual_cpu_ns'] = 2_100_000_000
        flow['settled_full_cpu_ns'] = 2_100_000_000
        flow['remaining_paid_credit_ns'] = flow['stored_credit_ns'] = -100_000_000
        with self.assertRaises(ValueError):
            reader.actual_depletion(altered)
        # Whole-report controls rehash all bytes, so the refusal must come from
        # accounting types rather than a stale digest or absent verifier file.
        for section, keys in [('final_actual_flow', flow_keys), ('final_meter', meter_keys)]:
            for key in keys:
                for invalid in (False, 0.0, -1):
                    with self.subTest(final_section=section, key=key, invalid=invalid), tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        report, _ = fixture(root)
                        report['phases'][0][section][key] = invalid
                        with self.assertRaises(ValueError):
                            self.read(root, report)

    def test_live_reservation_preserves_signed_stored_credit_and_paid_depletion(self):
        for remaining, owners, live, depleted in [
            (50_000_000, 1, 50_000_000, True),
            (0, 1, 100_000_000, True),
            (150_000_000, 2, 50_000_000, False),
        ]:
            with self.subTest(remaining=remaining, owners=owners):
                value = live_sample(remaining, owners, live)
                original = copy.deepcopy(value)
                self.assertLess(value['meter']['Ok']['actual_flow']['stored_credit_ns'], 0)
                self.assertIs(reader.actual_depletion(value), depleted)
                self.assertEqual(value, original)
        # These two public observations take separate locks. Only actual_flow's
        # own reservation/owner tuple is atomic; a prior meter is not that tuple.
        value = live_sample()
        value['meter']['Ok']['meter']['in_flight'] = 0
        self.assertTrue(reader.actual_depletion(value))

    def test_real_paid_deficit_stays_rejected_with_an_exact_live_escrow_identity(self):
        value = live_sample(-1, 1, 100_000_001)
        flow = value['meter']['Ok']['actual_flow']
        self.assertEqual(flow['initial_credit_ns'] - flow['paid_cpu_debit_ns'], -1)
        self.assertEqual(flow['stored_credit_ns'] + flow['booked_reservation_ns'], -1)
        self.assertEqual(flow['live_debited_cpu_ns'] + flow['settlement_residual_cpu_ns'],
                         flow['settled_full_cpu_ns'] + flow['unsettled_known_live_cpu_ns'])
        with self.assertRaises(ValueError):
            reader.actual_depletion(value)

    def test_reservation_requires_the_original_owner_count_and_full_start_quantum(self):
        for owners, booked in [(0, 100_000_000), (1, 0), (1, 200_000_000),
                               (2, 100_000_000), (3, 300_000_000)]:
            with self.subTest(owners=owners, booked=booked):
                value = live_sample(500_000_000)
                flow = value['meter']['Ok']['actual_flow']
                flow.update(live_owners=owners, booked_reservation_ns=booked,
                            stored_credit_ns=flow['remaining_paid_credit_ns'] - booked)
                # Keep the separately observed meter valid so the forged flow,
                # including its third owner, must fail its own exact invariant.
                value['meter']['Ok']['meter']['in_flight'] = 1
                self.assertGreaterEqual(flow['stored_credit_ns'], 0)
                with self.assertRaises(ValueError):
                    reader.actual_depletion(value)
        for invalid in (False, -50_000_000.0, -(1 << 127) - 1, 1 << 127):
            with self.subTest(stored_credit=invalid):
                value = live_sample()
                value['meter']['Ok']['actual_flow']['stored_credit_ns'] = invalid
                with self.assertRaises(ValueError):
                    reader.actual_depletion(value)
        value = live_sample(150_000_000, 2)
        self.assertFalse(reader.actual_depletion(value))
        value['meter']['Ok']['depleted'] = True
        with self.assertRaises(ValueError):
            reader.actual_depletion(value)
        value = live_sample()
        value['meter']['Ok']['meter']['in_flight'] = 3
        with self.assertRaises(ValueError):
            reader.actual_depletion(value)

    def test_actual_cpu_attribution_and_unsigned_counter_bounds_remain_exact(self):
        for key in ('settled_full_cpu_ns', 'unsettled_known_live_cpu_ns'):
            with self.subTest(key=key):
                value = live_sample(500_000_000)
                value['meter']['Ok']['actual_flow'][key] += 1
                with self.assertRaises(ValueError):
                    reader.actual_depletion(value)
        value = sample(True)
        flow = value['meter']['Ok']['actual_flow']
        # Equal fabricated additions preserve the old credit equality.
        flow['credited_refill_ns'] = flow['settlement_discard_ns'] = 1 << 64
        with self.assertRaises(ValueError):
            reader.actual_depletion(value)
        value = sample(True)
        flow = value['meter']['Ok']['actual_flow']
        # An algebraically balanced closed owner cannot retain live CPU.
        flow.update(live_debited_cpu_ns=1, settlement_residual_cpu_ns=1_949_999_999,
                    settled_full_cpu_ns=1_949_999_999, unsettled_known_live_cpu_ns=1)
        with self.assertRaises(ValueError):
            reader.actual_depletion(value)

    def test_full_report_retains_signed_live_credit_without_qualifying_original_red(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report, _ = fixture(root)
            report['phases'][1]['budget_samples'] = [live_sample()]
            report['phases'][1]['genuine_budget_depletion_observed'] = True
            original = copy.deepcopy(report)
            result = self.read(root, report)
            self.assertEqual(result['phases'][1]['actual_depletion_samples'], 1)
            self.assertFalse(result['original_criteria_met'])
            self.assertFalse(result['production_qualified'])
            self.assertEqual(report, original)
            for owners, live in ((1, 50_000_000), (2, 150_000_000)):
                with self.subTest(outstanding_final_owners=owners):
                    outstanding = live_sample(50_000_000, owners, live)['meter']['Ok']
                    # Every accounting identity is valid for this live sample.
                    # Only the terminal gate may refuse its unclosed owners;
                    # an inconsistent reservation would mask that requirement.
                    reader.actual_flow(outstanding['actual_flow'])
                    altered = copy.deepcopy(report)
                    phase = altered['phases'][1]
                    phase['final_actual_flow'] = outstanding['actual_flow']
                    phase['final_meter'] = outstanding['meter']
                    with self.assertRaisesRegex(ValueError, 'actual closed paid owner and complete settlement required'):
                        reader.phase_bindings(phase)
                    # read() rehashes the whole report and retains the native
                    # IPC fixtures, so this cannot pass via an earlier refusal.
                    with self.assertRaisesRegex(ValueError, 'actual closed paid owner and complete settlement required'):
                        self.read(root, altered)

    def test_duplicate_json_report_cannot_hide_an_earlier_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report, _ = fixture(root)
            raw = json.dumps(report).encode()
            raw = b'{"schema":"protected",' + raw[1:]
            path = root / 'report.json'
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                reader.read_report(path, hashlib.sha256(raw).hexdigest(), reader.POLICY_ID,
                                   native_fixture.BINARY, native_fixture.OUTER,
                                   reader.history_reader.STRICT_PROFILE)


if __name__ == '__main__':
    unittest.main()
