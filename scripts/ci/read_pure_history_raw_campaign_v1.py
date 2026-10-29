#!/usr/bin/env python3
"""Strict readback of the additional pure/raw-W1 + isolated History campaign.

This reader does not translate protected evidence into pure evidence. It reuses
the unchanged native History IPC/lifeline/resource reader, then checks zero
search receipts and the original finite criteria. Reading is not native replay.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pon_public_v3_policy_read import domain_hash, load_profiles
import read_native_history_verifier as history_reader
from pon_public_v3_phase_read import completion_work_observation, execution_summary

PROFILE = 'public-pure-pon-history-raw-development-v1'
WORK_PROFILE = 'pure-history-raw-v1'
SCHEMA = 'native-public-pure-history-raw-campaign-v1'
POLICY_ID = 'bf409dae237253a2ce14152c54198ed06e824e709763946e9c84e68e894eee58'
MAX_REPORT_BYTES = 256 * 1024 * 1024
CONTRACT = ('canonical-zero-solution-nonce/search-budget0/solution-trials0/no-admission-hashcash/'
            'full-original-W1-every-paid-submit/no-public-product-prefilter/no-rejection-cache/'
            'no-arithmetic-facts/original-shared-CPU-intake-workers-deadlines-and-verified-completion-priority/'
            'original-header-challenge-task-target-ticket-and-matrices/'
            'ordinary-native-journal-activation-cancellation-recovery-and-settlement/'
            'no-profile-negotiation-or-fallback/research-only-no-qualification')


def require(value, message):
    if not value:
        raise ValueError(message)


def integer(value):
    require(type(value) is int and value >= 0, 'exact nonnegative integer required')
    return value


@lru_cache(maxsize=1)
def expected_policy():
    config = load_profiles()
    require(config['current_revision'] == 'r13', 'pinned original r13 resource contract required')
    parts = [config['transport_profile'].encode('ascii'),
             config['revisions']['r13']['resource_contract'].encode('ascii'),
             bytes([0]), struct.pack('<Q', 2000),
             *(struct.pack('<Q', config[key]) for key in
               ('burst_ns', 'refill_ns_per_second', 'start_reserve_ns')),
             struct.pack('<I', config['worker_limit'])]
    original = domain_hash(config['hash_domain'], parts)
    identity = domain_hash('public-pure-pon-history-raw-resource-v1',
                           [PROFILE.encode('ascii'), bytes.fromhex(original), CONTRACT.encode('ascii')])
    require(identity == POLICY_ID, 'independently frozen signed resource policy vector required')
    return {'schema': 'public-pure-history-raw-resource-observation-v1',
            'transport_profile': PROFILE, 'policy_id': identity, 'ticket_bits': 0, 'lifetime_ms': 2000}


def require_policy(value):
    integer(value['ticket_bits'])
    integer(value['lifetime_ms'])
    require(value == expected_policy(), 'exact typed pure resource observation required')


def admission_call(row):
    policy = expected_policy()
    require_policy(row['public_resource_policy'])
    require(row['work_profile'] == WORK_PROFILE,
            'every call must bind the explicit pure/raw profile; protected receipts are not interchangeable')
    ack = row['pure_history_acknowledgement']
    require(set(ack) == {'schema', 'profile', 'policy_id', 'ticket_bits', 'search_budget',
                         'solution_trials', 'solution_nonce'}, 'complete exact acknowledgement receipt required')
    require(ack['schema'] == 'public-pure-history-raw-acknowledgement-v1'
            and ack['profile'] == PROFILE and ack['policy_id'] == policy['policy_id'],
            'exact signed resource namespace required')
    metrics = row['metrics']
    require(all(integer(ack[key]) == 0 for key in ('ticket_bits', 'search_budget', 'solution_trials'))
            and integer(metrics['solution_trials']) == 0
            and integer(metrics['solution_search_ns']) == 0, 'nonzero admission work is not pure evidence')
    require(type(metrics['solution_found']) is bool, 'actual acknowledgement stage required')
    if metrics['solution_found']:
        require(type(ack['solution_nonce']) is int and ack['solution_nonce'] == 0,
                'only canonical zero acknowledgement is permitted')
    else:
        require(ack['solution_nonce'] is None, 'unreached acknowledgement cannot have a nonce')
    require(row['status'] in ('ok', 'refused', 'error'), 'original call status required')
    if row['status'] != 'error':
        require(metrics['solution_found'] and integer(row['response']['solve_trials']) == 0,
                'successful authenticated reply must retain actual zero-search receipt')


def original_meter(meter):
    for key in ('burst_ns', 'refill_ns_per_second', 'start_reserve_ns', 'worker_limit', 'in_flight'):
        integer(meter[key])
    require(type(meter['accounting_unavailable']) is bool, 'actual accounting-availability flag required')
    require(meter['burst_ns'] == 2_000_000_000
            and meter['refill_ns_per_second'] == 250_000_000
            and meter['start_reserve_ns'] == 100_000_000 and meter['worker_limit'] == 2,
            'original paid CPU budget must remain unchanged')


def actual_flow(flow):
    require(flow is not None and flow['balance_identity_verified'] is True,
            'actual paid CPU conservation observation required')
    for key in ('initial_credit_ns', 'credited_refill_ns', 'paid_cpu_debit_ns',
                'settlement_discard_ns', 'remaining_paid_credit_ns', 'stored_credit_ns',
                'booked_reservation_ns', 'live_debited_cpu_ns', 'settlement_residual_cpu_ns',
                'live_owners', 'unsettled_known_live_cpu_ns'):
        integer(flow[key])
    require(flow['initial_credit_ns'] == 2_000_000_000, 'original initial paid credit required')
    require(flow['initial_credit_ns'] + flow['credited_refill_ns'] - flow['paid_cpu_debit_ns']
            - flow['settlement_discard_ns'] == flow['remaining_paid_credit_ns']
            == flow['stored_credit_ns'] + flow['booked_reservation_ns'], 'actual credit identity mismatch')
    require(flow['paid_cpu_debit_ns'] == flow['live_debited_cpu_ns'] + flow['settlement_residual_cpu_ns'],
            'actual paid debit identity mismatch')


def actual_depletion(sample):
    observation = sample['meter']['Ok']
    flow, meter = observation['actual_flow'], observation['meter']
    original_meter(meter)
    actual_flow(flow)
    integer(observation['clock_failures'])
    require(type(observation['depleted']) is bool, 'actual depletion outcome flag required')
    depleted = (flow['remaining_paid_credit_ns'] < 100_000_000
                and flow['paid_cpu_debit_ns'] > 1_900_000_000
                and observation['clock_failures'] == 0 and meter['accounting_unavailable'] is False)
    require(observation['depleted'] is depleted, 'original depletion predicate disagrees with actual ledger')
    return depleted


def phase_bindings(phase):
    require_policy(phase['public_resource_policy'])
    require(phase['work_profile'] == WORK_PROFILE, 'pure phase binding required')
    for key in ('duration_seconds', 'attacker_processes_requested', 'attacker_processes_ready',
                'full_work_failed', 'full_work_accepted'):
        integer(phase[key])
    for value in phase['attack_calls_overlapping_each_signed_round']:
        integer(value)
    require(phase['duration_seconds'] == 30 and phase['state_backend'] == 'authenticated-v1',
            'original window and authenticated state required')
    mode = phase['mode']
    requested = 0 if mode == 'baseline' else 24
    require(phase['attacker_processes_requested'] == requested, 'original actor count required')
    calls = [*phase['submissions'], *phase['history']]
    for child in phase['children']:
        report = child['report']['result']
        require_policy(report['public_resource_policy'])
        require(report['work_profile'] == WORK_PROFILE,
                'pure actor result binding required')
        calls.extend(report['calls'])
    require(bool(calls), 'actual native call receipts required')
    for call in calls:
        admission_call(call)
    require(phase['pure_history_acknowledgements_verified'] is True,
            'native pure acknowledgement conjunct must have run')
    samples = phase['budget_samples']
    require(bool(samples), 'actual original budget samples required')
    depleted = [sample for sample in samples if actual_depletion(sample)]
    require(phase['genuine_budget_depletion_observed'] is bool(depleted),
            'original depletion result must agree with raw samples')
    flow = phase['final_actual_flow']
    actual_flow(flow)
    original_meter(phase['final_meter'])
    require(flow['balance_identity_verified'] is True
            and flow['live_owners'] == flow['booked_reservation_ns']
                == flow['unsettled_known_live_cpu_ns'] == 0
            and phase['final_meter']['in_flight'] == 0
            and phase['final_meter']['accounting_unavailable'] is False,
            'actual closed paid owner and complete settlement required')
    require(phase['receiver_client_state_equal'] is True, 'original full state equality is mandatory')
    require('work_arithmetic_owner' not in phase, 'raw campaign cannot substitute an arithmetic cache owner')
    completion_work_observation(phase['completion_work_observation'])
    observer = phase['receiver_observation']
    require(observer['schema'] == 'public-v3-local-request-resource-observation-v3'
            and observer['cpu_intervals_are_nested_not_additive'] is True
            and observer['cpu_includes_reactor_authentication_or_response_signing'] is True
            and observer['cpu_includes_reactor_authentication'] is False
            and observer['dispatch_cpu_includes_paid_body_decode'] is True
            and observer['dispatch_cpu_includes_response_signing'] is True
            and observer['submit_phase_cpu_excludes_scoped_workers'] is True,
            'unchanged raw r13 paid body, dispatch and signing CPU observation required')
    execution_summary(observer['records'], instrumented=True, arithmetic_profile=False)
    require(phase['full_work_failed'] == sum(row['full_work_accepted'] is False for row in observer['records'])
            and phase['full_work_accepted'] == sum(row['full_work_accepted'] is True for row in observer['records']),
            'actual receiver full W1 outcomes must match retained counts')
    rounds = phase['confirmations']
    all_in_window = len(rounds) == 3 and all(row['confirmed_inside_pressure_window'] is True for row in rounds)
    for row in rounds:
        if row['confirmed_inside_pressure_window'] is True:
            observation = row['observation']
            require(integer(row['ended_ns']) < 30_000_000_000 and observation is not None
                    and observation['confirmed'] is True and observation['finalized'] is False
                    and observation['execution_authority'] is False and integer(observation['depth']) == 6,
                    'original depth-six, non-authoritative in-window confirmation required')
    require(phase['all_signed_rounds_confirmed_in_window'] is all_in_window,
            'original in-window confirmation outcome must be retained')
    if phase['finite_phase_criteria_met'] is True:
        integer(phase['service_outcome']['Ok']['mutation_cpu_clock_failures'])
        require(all_in_window and phase['observer_complete'] is True and not phase['verifier_errors']
                and phase['service_outcome']['Ok']['mutation_cpu_clock_failures'] == 0,
                'true phase requires complete original confirmation and observations')
        if mode != 'baseline':
            require(bool(depleted) and phase['attacker_processes_ready'] == 24
                    and phase['actor_reports_successful_without_cap_or_kill'] is True
                    and phase['full_work_failed'] > 0 and phase['full_work_accepted'] >= 21
                    and len(phase['attack_calls_overlapping_each_signed_round']) == 3
                    and all(n > 0 for n in phase['attack_calls_overlapping_each_signed_round'])
                    and any(row['paid_credit_depletion_observed_during_round'] is True for row in rounds)
                    and all(row['receiver_hostile_work_rejected_during_round'] is True for row in rounds)
                    and all(call['status'] != 'ok' for child in phase['children']
                            for call in child['report']['result']['calls']),
                    'all original attack, depletion and overlap requirements remain mandatory')
    return {'mode': mode, 'actual_zero_search_calls': len(calls), 'budget_samples': len(samples),
            'actual_depletion_samples': len(depleted), 'original_phase_criteria_met': phase['finite_phase_criteria_met']}


def read_report(path, expected_sha256, expected_policy_id, binary_sha256, outer_cgroup, expected_history_profile):
    path = Path(path)
    require(path.is_file() and not path.is_symlink()
            and path.stat().st_size <= MAX_REPORT_BYTES, 'bounded regular raw report required')
    with path.open('rb') as source:
        raw = source.read(MAX_REPORT_BYTES + 1)
    require(len(raw) <= MAX_REPORT_BYTES and hashlib.sha256(raw).hexdigest() == expected_sha256,
            'original raw report SHA256 mismatch')
    def unique(rows):
        value = {}
        for key, item in rows:
            require(key not in value, 'duplicate raw report key refused')
            value[key] = item
        return value
    report = json.loads(raw, object_pairs_hook=unique,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite raw report')))
    require(report['schema'] == SCHEMA and report['work_profile'] == WORK_PROFILE,
            'only the separate pure/raw History campaign schema is accepted')
    require_policy(report['public_resource_policy'])
    require(expected_policy_id == expected_policy()['policy_id'], 'pinned pure policy required')
    for key in ('actual_signed_seed_transfers', 'seed_blocks', 'business_blocks'):
        integer(report['preparation'][key])
    require(report['state_backend'] == 'authenticated-v1'
            and report['preparation']['actual_signed_seed_transfers'] == 1024
            and report['preparation']['seed_blocks'] == 4
            and report['preparation']['business_blocks'] == 21,
            'original signed seed and business workload required')
    require([row['mode'] for row in report['phases']] == ['baseline', 'from-zero', 'late-product'],
            'original input mix required')
    # This always reads the actual independent process/IPC/cgroup/lifeline
    # evidence. There is no flag that accepts an in-process substitute.
    native = history_reader.validate_report(report, path.parent, binary_sha256, outer_cgroup,
                                            expected_history_profile)
    phases = [phase_bindings(phase) for phase in report['phases']]
    complete = (report['finite_experiment_criteria_met'] is True
                and report['economics_complete'] is True
                and all(row['original_phase_criteria_met'] is True for row in phases)
                and native['complete'] is True)
    return {'schema': 'pure-history-raw-independent-readback-v1', 'source_report_sha256': expected_sha256,
            'public_resource_policy': expected_policy(), 'history_resource_profile': expected_history_profile,
            'phases': phases, 'native_history': native, 'original_criteria_met': complete,
            'protected_evidence_substitution_allowed': False, 'production_qualified': False}
