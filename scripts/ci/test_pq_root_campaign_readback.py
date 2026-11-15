"""Small synthetic negative controls for the original campaign ZIP reader.

Not an independent external operation, security proof or performance test.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import io
import json
import unittest
import zipfile

import pq_root_campaign_readback as reader

TX = 'tx-constant-fixture-not-production-effect'


def synthetic():
    result = {
        'original_inputs': deepcopy(reader.EXPECTED_INPUTS),
        'public_phase_placement': {
            'receiver_and_verifier_cpu_max': '25000 100000',
            'receiver_and_verifier_memory_max': '2147483648',
            'fixed_parent': reader.FIXED_PARENT,
            'original_3x3_workload_and_depletion_predicates_changed': False,
        },
        'attempts': [{'number': i, 'original_criteria_met': False,
                      'complete_success': False, 'step': {'returncode': 101}}
                     for i in (1, 2, 3)],
    }
    host = {'limits': deepcopy(reader.FIXED_LIMITS),
            'parent_path': reader.FIXED_PARENT,
            'parent': {'canonical_path': reader.FIXED_PARENT, 'uid': 0,
                       'directory': True, 'symlink': False}, 'read_errors': {}}
    def phase(mode, attackers):
        c = {'round': 0, 'confirmed_inside_pressure_window': mode == 'baseline',
             'ended_ns': 28_000_000_000, 'transaction': TX,
             'included_block': 'block-fixture', 'tip': 'tip-fixture',
             'started_ns': 1_000_000_000,
             'observation': {'confirmed': mode == 'baseline', 'transaction': TX,
                             'depth': 6, 'reorged': False,
                             'included_height': 5, 'observed_height': 11,
                             'included_block': 'block-fixture',
                             'observed_tip': 'tip-fixture',
                             'finalized': False, 'execution_authority': False}}
        return {'mode': mode, 'duration_seconds': 30,
                'attacker_processes_requested': attackers,
                'finite_phase_criteria_met': False,
                'all_signed_rounds_confirmed_in_window': False,
                'receiver_client_state_equal': False,
                'genuine_budget_depletion_observed': False,
                'depletion_at_ns': None, 'depletion_meter': None,
                'final_receiver_tip': 'a' * 64, 'final_client_tip': 'b' * 64,
                'attacker_processes_ready': attackers,
                'actor_reports_successful_without_cap_or_kill': True,
                'full_work_failed': 0,
                'confirmations': [c], 'history': [{
                    'status': 'ok', 'response': {'ok': True},
                    'client_import': {'succeeded': True},
                }]}
    reports = [{'finite_experiment_criteria_met': False,
                'phases': [phase(mode, count) for mode, count in
                           zip(reader.EXPECTED_INPUTS['modes'], [0, 24, 24])]}
               for _ in range(3)]
    return result, reports, [deepcopy(host) for _ in range(9)]


class EvidenceReaderTests(unittest.TestCase):
    def assert_refused(self, data, label):
        with self.assertRaises(reader.EvidenceError, msg=label):
            reader.summarize(*data)

    def test_three_repeated_confirmations_are_one_fixture_identity_not_paid_effects(self):
        report = reader.summarize(*synthetic())
        self.assertEqual(report['window_confirmations'], 3)
        self.assertEqual(report['distinct_fixture_transactions'], 1)
        self.assertEqual(report['complete_original_campaigns'], 0)
        self.assertFalse(report['all_observed_window_confirmations_have_finality'])
        self.assertFalse(report['all_observed_window_confirmations_have_execution_authority'])
        self.assertIsNone(report['actual_lifetime_failure_bound'])
        self.assertEqual(report['status'], 'HOLD_NO_GO')

    def test_tampered_workload_is_refused(self):
        data = synthetic(); data[0]['original_inputs']['phase_seconds'] = 31
        self.assert_refused(data, 'must keep 30s')

    def test_tampered_attacker_denominator_is_refused(self):
        data = synthetic(); data[1][0]['phases'][1]['attacker_processes_requested'] = 0
        self.assert_refused(data, 'must keep 24 hostile')

    def test_tampered_cpu_and_memory_are_refused(self):
        for key, value in [('cpu.max', '50000 100000'), ('memory.max', '4294967296')]:
            data = synthetic(); data[2][0]['limits'][key] = value
            self.assert_refused(data, key)

    def test_untrusted_parent_is_refused(self):
        data = synthetic(); data[2][4]['parent']['uid'] = 1000
        self.assert_refused(data, 'root-owned parent')

    def test_missing_one_original_campaign_is_refused(self):
        data = synthetic(); data[0]['attempts'].pop()
        self.assert_refused(data, 'three campaigns')

    def test_false_in_window_confirmation_is_refused(self):
        data = synthetic()
        data[1][0]['phases'][0]['confirmations'][0]['observation']['confirmed'] = False
        self.assert_refused(data, 'forged confirmation')

    def test_late_confirmation_cannot_be_relabelled_in_window(self):
        data = synthetic()
        data[1][0]['phases'][0]['confirmations'][0]['ended_ns'] = 30_000_000_001
        self.assert_refused(data, 'deadline')

    def test_import_success_without_rpc_is_refused(self):
        data = synthetic()
        data[1][0]['phases'][0]['history'][0]['status'] = 'timeout'
        self.assert_refused(data, 'rpc vs native import')

    def test_forged_phase_success_without_three_confirmations_is_refused(self):
        data = synthetic()
        data[1][0]['phases'][0]['finite_phase_criteria_met'] = True
        self.assert_refused(data, 'forged phase success')

    def test_forged_campaign_success_without_three_phases_is_refused(self):
        data = synthetic()
        data[0]['attempts'][0]['complete_success'] = True
        data[0]['attempts'][0]['original_criteria_met'] = True
        data[0]['attempts'][0]['step']['returncode'] = 0
        self.assert_refused(data, 'forged campaign success')

    def test_duplicate_round_zero_cannot_be_counted_as_three_signed_rounds(self):
        data = synthetic()
        phase = data[1][0]['phases'][0]
        phase['confirmations'] *= 3
        phase['all_signed_rounds_confirmed_in_window'] = True
        phase['finite_phase_criteria_met'] = True
        phase['receiver_client_state_equal'] = True
        phase['observer_complete'] = True
        self.assert_refused(data, 'duplicate round-zero')

    def test_distinct_rounds_cannot_reuse_one_transaction(self):
        data = synthetic()
        phase = data[1][0]['phases'][0]
        confirmations = []
        for i in range(3):
            c = deepcopy(phase['confirmations'][0])
            c['round'] = i
            c['started_ns'], c['ended_ns'] = i * 10 + 1, i * 10 + 9
            confirmations.append(c)
        phase['confirmations'] = confirmations
        phase['all_signed_rounds_confirmed_in_window'] = True
        phase['finite_phase_criteria_met'] = True
        phase['receiver_client_state_equal'] = True
        phase['observer_complete'] = True
        self.assert_refused(data, 'one transaction across three rounds')

    def test_malformed_confirmation_clock_is_refused(self):
        data = synthetic()
        c = data[1][0]['phases'][0]['confirmations'][0]
        c['started_ns'] = c['ended_ns'] + 1
        self.assert_refused(data, 'negative confirmation duration')

    def test_six_depth_signed_inclusion_mismatch_is_refused(self):
        for key, bad in [('depth', 5), ('included_block', 'other-block'),
                         ('observed_tip', 'other-tip'), ('reorged', True)]:
            data = synthetic()
            data[1][0]['phases'][0]['confirmations'][0]['observation'][key] = bad
            self.assert_refused(data, f'six-depth signed inclusion: {key}')

    def test_claimed_three_signed_rounds_without_three_confirmations_is_refused(self):
        data = synthetic()
        data[1][0]['phases'][0]['all_signed_rounds_confirmed_in_window'] = True
        self.assert_refused(data, 'three signed rounds required')

    def ready_attack_phase(self):
        """Construct an isolated positive phase; never label a whole run PASS."""
        data = synthetic()
        p = data[1][0]['phases'][1]
        base = deepcopy(data[1][0]['phases'][0]['confirmations'][0])
        rounds = []
        for i in range(3):
            c = deepcopy(base)
            c['round'] = i
            c['started_ns'] = 1_000_000_000 + i * 9_000_000_000
            c['ended_ns'] = c['started_ns'] + 2_000_000_000
            c['transaction'] = f'synthetic-independent-round-{i}'
            c['observation']['transaction'] = c['transaction']
            rounds.append(c)
        p.update(confirmations=rounds, all_signed_rounds_confirmed_in_window=True,
                 finite_phase_criteria_met=True, receiver_client_state_equal=True,
                 observer_complete=True, genuine_budget_depletion_observed=True,
                 attacker_processes_ready=24, full_work_failed=100,
                 final_receiver_tip='a' * 64, final_client_tip='a' * 64,
                 depletion_at_ns=20_000_000_000,
                 depletion_meter={'Ok': {
                     'depleted': True, 'clock_failures': 0,
                     'meter': {'accounting_unavailable': False,
                               'schema': 'public-v3-local-stored-cpu-budget-v1',
                               'burst_ns': 2_000_000_000,
                               'refill_ns_per_second': 250_000_000,
                               'start_reserve_ns': 100_000_000,
                               'worker_limit': 2,
                               'stored_credit_ns': 49_999_999},
                     'actual_flow': {
                         'balance_identity_verified': True,
                         'schema': 'public-v3-local-actual-cpu-flow-v1',
                         'initial_credit_ns': 2_000_000_000,
                         'credited_refill_ns': 0,
                         'paid_cpu_debit_ns': 1_950_000_001,
                         'live_debited_cpu_ns': 1_950_000_001,
                         'settlement_residual_cpu_ns': 0,
                         'settlement_discard_ns': 0,
                         'booked_reservation_ns': 0,
                         'live_owners': 0,
                         'unsettled_known_live_cpu_ns': 0,
                         'settled_full_cpu_ns': 1_950_000_001,
                         'stored_credit_ns': 49_999_999,
                         'remaining_paid_credit_ns': 49_999_999,
                     },
                 }})
        return data

    def test_fully_ready_attack_phase_has_only_local_report_scope(self):
        observation = reader.summarize(*self.ready_attack_phase())
        self.assertEqual(observation['attack_phases'], 6)
        self.assertEqual(observation['attack_phases_with_genuine_budget_depletion'], 1)
        self.assertEqual(observation['attack_phases_with_full_actor_readiness'], 6)
        self.assertTrue(observation['phases'][1]['phase_criteria_met'])
        self.assertEqual(observation['complete_original_campaigns'], 0)
        self.assertEqual(observation['status'], 'HOLD_NO_GO')

    def test_attack_phase_cannot_pass_with_missing_depletion(self):
        data = self.ready_attack_phase()
        data[1][0]['phases'][1]['genuine_budget_depletion_observed'] = False
        self.assert_refused(data, 'original hostile depletion missing')

    def test_attack_phase_cannot_pass_with_missing_hostile_actor(self):
        data = self.ready_attack_phase()
        data[1][0]['phases'][1]['attacker_processes_ready'] = 23
        self.assert_refused(data, '23 instead of 24')

    def test_attack_phase_cannot_pass_with_incomplete_actor_report(self):
        data = self.ready_attack_phase()
        data[1][0]['phases'][1]['actor_reports_successful_without_cap_or_kill'] = False
        self.assert_refused(data, 'actor report failure')

    def test_negative_or_noninteger_original_work_count_is_refused(self):
        for value in (-1, True, '100'):
            data = self.ready_attack_phase()
            data[1][0]['phases'][1]['full_work_failed'] = value
            self.assert_refused(data, 'forged work count')

    def test_equal_state_claim_refuses_different_final_tips(self):
        data = self.ready_attack_phase()
        data[1][0]['phases'][1]['final_client_tip'] = 'b' * 64
        self.assert_refused(data, 'one state-equal flag cannot hide divergent tips')

    def test_equal_state_claim_requires_real_hex_tip_bytes(self):
        for invalid in (None, 'short', 'g' * 64):
            data = self.ready_attack_phase()
            data[1][0]['phases'][1]['final_receiver_tip'] = invalid
            self.assert_refused(data, 'missing or malformed final receiver tip')

    def test_depletion_claim_without_raw_meter_is_refused(self):
        data = self.ready_attack_phase()
        data[1][0]['phases'][1]['depletion_meter'] = None
        self.assert_refused(data, 'boolean cannot replace an actual meter')

    def test_depletion_meter_must_have_paid_accounting_identity(self):
        for key, value in [('depleted', False), ('actual_flow', {'balance_identity_verified': False}),
                           ('meter', {'accounting_unavailable': True})]:
            data = self.ready_attack_phase()
            data[1][0]['phases'][1]['depletion_meter']['Ok'][key] = value
            self.assert_refused(data, 'depletion without complete meter corroboration')

    def test_depletion_claim_rejects_nonatomic_meter_flow_credit(self):
        data = self.ready_attack_phase()
        data[1][0]['phases'][1]['depletion_meter']['Ok']['meter']['stored_credit_ns'] += 1
        self.assert_refused(data, 'meter and accounted credit differ')

    def test_depletion_claim_rejects_nonconserved_paid_flow(self):
        for key, value in [('paid_cpu_debit_ns', 1_950_000_000),
                           ('booked_reservation_ns', 100_000_000),
                           ('remaining_paid_credit_ns', 49_999_998)]:
            data = self.ready_attack_phase()
            data[1][0]['phases'][1]['depletion_meter']['Ok']['actual_flow'][key] = value
            self.assert_refused(data, 'paid ledger must balance')

    def test_depletion_claim_rejects_nonoriginal_cpu_profile(self):
        for field, value in [('refill_ns_per_second', 0), ('burst_ns', 1_000_000_000),
                             ('start_reserve_ns', 1), ('schema', 'fake')]:
            data = self.ready_attack_phase()
            data[1][0]['phases'][1]['depletion_meter']['Ok']['meter'][field] = value
            self.assert_refused(data, 'meter profile must be original')

    def test_depletion_claim_requires_below_original_start_reserve(self):
        data = self.ready_attack_phase()
        obj = data[1][0]['phases'][1]['depletion_meter']['Ok']
        obj['meter']['stored_credit_ns'] = 150_000_000
        obj['actual_flow']['stored_credit_ns'] = 150_000_000
        obj['actual_flow']['remaining_paid_credit_ns'] = 150_000_000
        obj['actual_flow']['paid_cpu_debit_ns'] = 1_850_000_000
        self.assert_refused(data, 'not depleted with credit above reserve')

    def test_depletion_claim_rejects_noninteger_credit(self):
        data = self.ready_attack_phase()
        data[1][0]['phases'][1]['depletion_meter']['Ok']['actual_flow']['stored_credit_ns'] = True
        self.assert_refused(data, 'boolean credit is invalid')

    def test_depletion_timestamp_must_be_inside_original_window(self):
        for invalid in (None, True, 30_000_000_001, -1):
            data = self.ready_attack_phase()
            data[1][0]['phases'][1]['depletion_at_ns'] = invalid
            self.assert_refused(data, 'depletion outside 30s, missing or bool clock')

    def test_raw_success_claim_flags_must_have_boolean_types(self):
        for field in ('receiver_client_state_equal', 'genuine_budget_depletion_observed'):
            for invalid in (1, 'true', None):
                data = self.ready_attack_phase()
                data[1][0]['phases'][1][field] = invalid
                self.assert_refused(data, 'nonboolean claims cannot be coerced')

    def test_booked_but_unspent_credit_cannot_fake_paid_depletion(self):
        # On #933 this passed: stored=0, booked=2B, debit=0, remaining=2B.
        # It satisfies the weak previous stored-credit identity, but not
        # the original paid-CPU or remaining-credit requirements.
        data = self.ready_attack_phase()
        obj = data[1][0]['phases'][1]['depletion_meter']['Ok']
        obj['meter']['stored_credit_ns'] = 0
        flow = obj['actual_flow']
        flow.update(paid_cpu_debit_ns=0, live_debited_cpu_ns=0,
                    settled_full_cpu_ns=0, booked_reservation_ns=2_000_000_000,
                    live_owners=20, remaining_paid_credit_ns=2_000_000_000,
                    stored_credit_ns=0)
        self.assert_refused(data, 'booked reservation is not actually paid')

    def test_original_paid_threshold_must_be_strict(self):
        data = self.ready_attack_phase()
        obj = data[1][0]['phases'][1]['depletion_meter']['Ok']
        obj['actual_flow'].update(
            paid_cpu_debit_ns=1_900_000_000,
            live_debited_cpu_ns=1_900_000_000,
            settled_full_cpu_ns=1_900_000_000,
            settlement_discard_ns=50_000_001)
        self.assert_refused(data, '1.9B precisely is not > 1.9B')

    def test_original_settlement_discard_is_accounted_not_omitted(self):
        # Positive value is possible under the original conservation
        # equation; earlier #933 verifier refused it without justification.
        data = self.ready_attack_phase()
        obj = data[1][0]['phases'][1]['depletion_meter']['Ok']
        obj['actual_flow'].update(
            paid_cpu_debit_ns=1_900_000_001,
            live_debited_cpu_ns=1_900_000_001,
            settled_full_cpu_ns=1_900_000_001,
            settlement_discard_ns=50_000_000)
        self.assertTrue(reader.summarize(*data)['phases'][1]['phase_criteria_met'])

    def test_original_live_owner_and_clock_witness_are_required(self):
        for field, value in [('live_owners', 1),
                             ('unsettled_known_live_cpu_ns', 1),
                             ('live_debited_cpu_ns', 1)]:
            data = self.ready_attack_phase()
            data[1][0]['phases'][1]['depletion_meter']['Ok']['actual_flow'][field] = value
            self.assert_refused(data, field)
        for key, value in [('clock_failures', 1), ('clock_failures', True)]:
            data = self.ready_attack_phase()
            data[1][0]['phases'][1]['depletion_meter']['Ok'][key] = value
            self.assert_refused(data, key)
        data = self.ready_attack_phase()
        data[1][0]['phases'][1]['depletion_meter']['Ok']['meter']['worker_limit'] = 3
        self.assert_refused(data, 'worker_limit changed')

    def test_zip_manifest_integrity_and_mutated_member(self):
        def make_archive(manifest_digest=None, path='body.txt'):
            raw = b'test payload'
            m = {'files': [{'path': path, 'bytes': len(raw),
                            'sha256': manifest_digest or hashlib.sha256(raw).hexdigest()}]}
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
                z.writestr(path, raw)
                z.writestr('artifact-files.json', json.dumps(m))
            buf.seek(0)
            return buf
        with zipfile.ZipFile(make_archive()) as z:
            self.assertEqual(reader.verify_zip(z)['manifest_payload_entries'], 1)
        with zipfile.ZipFile(make_archive(manifest_digest='0' * 64)) as z:
            with self.assertRaises(reader.EvidenceError): reader.verify_zip(z)
        with zipfile.ZipFile(make_archive(path='../escape.txt')) as z:
            with self.assertRaises(reader.EvidenceError): reader.verify_zip(z)

    def test_zip_member_not_listed_in_manifest_is_refused(self):
        m = {'files': [{'path': 'a.txt', 'bytes': 1,
                        'sha256': hashlib.sha256(b'a').hexdigest()}]}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('a.txt', b'a')
            z.writestr('extra.txt', b'x')
            z.writestr('artifact-files.json', json.dumps(m))
        buf.seek(0)
        with zipfile.ZipFile(buf) as z:
            with self.assertRaises(reader.EvidenceError): reader.verify_zip(z)


if __name__ == '__main__':
    unittest.main()
