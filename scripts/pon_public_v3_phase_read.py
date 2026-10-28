#!/usr/bin/env python3
"""Read retained multiprocess observations; never infer confirmations from ACKs.

Historical v1/v2 and the r11/r12/r13 paid CPU envelope's v3 observations are accepted.
The separate arithmetic-facts campaign retains its own schema and signed profile;
reading it cannot qualify raw r13 or arbitrary-key service.
An explicit observed policy is checked against exact revision vectors. Missing
historical policy metadata is not inferred from the shared observer schema.
Missing measurements stay unknown. This reader does not run native admission,
authenticate a host/source claim or issue a production qualification.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys

from pon_public_v3_policy_read import ARITHMETIC_PROFILE, ARITHMETIC_REVISION, identify_observation

PHASES = ('decode', 'context_owner_wait', 'context', 'work',
          'admission_owner_wait', 'admission', 'submit_result')
MODES = ('baseline', 'from-zero', 'late-product')
ROUNDS = 3
MAX_REPORT_BYTES = 256 * 1024 * 1024
ARITHMETIC_REPORT_SCHEMA = 'native-public-v3-arithmetic-facts-separate-process-campaign-v1'


def require(value, message):
    if not value:
        raise ValueError(message)


def integer(value):
    require(type(value) is int and value >= 0, 'nonnegative integer observation required')
    return value


def stats(values):
    known = sorted(integer(value) for value in values if value is not None)
    n = len(known)
    return {'known_count': n, 'unknown_count': len(values) - n,
            'sum_known_ns': sum(known), 'min_ns': known[0] if n else None,
            'p50_nearest_rank_ns': known[(n - 1) // 2] if n else None,
            'p95_nearest_rank_ns': known[(95 * n + 99) // 100 - 1] if n else None,
            'max_ns': known[-1] if n else None,
            'mean_known_ns': {'numerator': sum(known), 'denominator': n} if n else None}


def outcome(value):
    require(value is None or type(value) is bool, 'boolean or unknown outcome required')
    return 'accepted' if value is True else 'rejected' if value is False else 'unknown'


def digest(value):
    if value is None:
        return None
    if isinstance(value, list):
        require(len(value) == 32 and all(type(n) is int and 0 <= n <= 255 for n in value),
                'canonical observed 32-byte digest required')
        return bytes(value).hex()
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value),
            'canonical observed digest required')
    return value


def refusal_error(row):
    """Project the native reply envelope, keeping retained legacy flat errors.

    Unknown is retained when neither shape recorded an error. Conflicting
    shapes cannot be silently attributed to either error or called successful.
    """
    response = row.get('response')
    if response is None:
        return None
    require(isinstance(response, dict), 'response object required')
    value = response.get('value')
    require(value is None or isinstance(value, dict), 'response value object required')
    flat, nested = response.get('error'), (value or {}).get('error')
    for error in (flat, nested):
        require(error is None or isinstance(error, str), 'observed refusal error string required')
    require(flat is None or nested is None or flat == nested,
            'conflicting flat and nested refusal errors')
    return nested if nested is not None else flat


def call_summary(rows):
    on_time = [row for row in rows if row['status'] == 'ok'
               and row['returned_after_window'] is False]
    return {'attempts': len(rows), 'status_counts': dict(Counter(row['status'] for row in rows)),
            'acknowledged_on_time': len(on_time),
            'acknowledged_after_window': sum(row['status'] == 'ok'
                and row['returned_after_window'] is True for row in rows),
            'all_calls_returned_after_window': sum(row['returned_after_window'] is True for row in rows),
            'on_time_unique_packet_indices': sorted({integer(row['packet_index']) for row in on_time
                                                     if 'packet_index' in row}),
            'errors': dict(Counter(str(row['error']) for row in rows if row.get('error') is not None)),
            'refusals': dict(Counter(str(refusal_error(row)) for row in rows
                                    if row['status'] == 'refused')),
            'elapsed_wall_ns': stats([row.get('elapsed_wall_ns') for row in rows]),
            'calling_process_cpu_ns': stats([row.get('calling_process_cpu_ns') for row in rows])}


def arithmetic_observation(value):
    require(type(value) is dict and set(value) == {'schema', 'slots', 'retained_software_bytes',
            'completed', 'arithmetic'} and value['schema'] == 'public-v3-work-arithmetic-observation-v1'
            and type(value['slots']) is int and value['slots'] == 64
            and type(value['retained_software_bytes']) is int
            and 0 < value['retained_software_bytes'] <= 4 * 1024 * 1024
            and type(value['completed']) is bool, 'exact bounded arithmetic observation required')
    actual = value['arithmetic']
    if not value['completed']:
        require(actual is None, 'unfinished arithmetic observation cannot claim completed facts')
        return value
    flags = ('lookup_contended', 'exact_fact_found', 'trace_reused', 'product_reused',
             'transcript_entered', 'transcript_completed', 'product_entered', 'product_completed')
    require(type(actual) is dict and set(actual) == {*flags, 'lookup_probes', 'publication_probes',
            'publication'} and all(type(actual[key]) is bool for key in flags)
            and all(type(actual[key]) is int and 0 <= actual[key] <= 64
                    for key in ('lookup_probes', 'publication_probes'))
            and actual['publication'] in ('none', 'trace', 'product', 'existing-stronger-or-equal',
                                          'contended'), 'exact arithmetic path facts required')
    require((not actual['product_reused'] or actual['trace_reused'])
            and (not actual['trace_reused'] or actual['exact_fact_found'])
            and not (actual['trace_reused'] and actual['transcript_entered'])
            and (not actual['transcript_completed'] or actual['transcript_entered'])
            and (not actual['product_entered'] or actual['transcript_completed'])
            and (not actual['product_completed'] or actual['product_entered'])
            and (not actual['lookup_contended'] or
                 (actual['lookup_probes'] == 0 and not actual['exact_fact_found']))
            and (actual['publication'] not in ('trace', 'product', 'existing-stronger-or-equal')
                 or actual['transcript_completed'])
            and (actual['publication'] != 'product' or actual['product_completed']),
            'inconsistent reused versus recomputed arithmetic facts')
    return value


def execution_summary(rows, instrumented, arithmetic_profile=False):
    result = {
        'records': len(rows),
        'record_complete': sum(row.get('complete') is True for row in rows),
        'record_observation_failed': sum(row.get('observation_failed') is True for row in rows),
        'terminal_phase_counts': dict(Counter(str(row.get('terminal_phase')) for row in rows)),
        'dispatch_outcomes': dict(Counter(outcome(row.get('dispatch_accepted')) for row in rows)),
        'full_work_outcomes': dict(Counter(outcome(row.get('full_work_accepted')) for row in rows)),
        'dispatch_thread_cpu_ns': stats([row.get('dispatch_thread_cpu_ns') for row in rows
                                         if row.get('dispatch_started') is True]),
        'full_work_thread_cpu_ns': stats([row.get('full_work_thread_cpu_ns') for row in rows
                                          if row.get('full_work_started') is True]),
        'submit_phase_measurements_available': instrumented,
        'submit_phases': None,
    }
    if arithmetic_profile:
        known = [arithmetic_observation(row['work_arithmetic']) for row in rows
                 if 'work_arithmetic' in row]
        actual = [row['arithmetic'] for row in known if row['completed']]
        result['work_arithmetic'] = {
            'observed_records': len(known), 'unobserved_records': len(rows) - len(known),
            'completed_observations': len(actual),
            'unfinished_observations': len(known) - len(actual),
            'path_counts': {key: sum(row[key] for row in actual) for key in
                ('trace_reused', 'product_reused', 'transcript_entered', 'transcript_completed',
                 'product_entered', 'product_completed')},
            'publication_counts': dict(Counter(row['publication'] for row in actual)),
            'scope': 'observed path facts only; completion is not acceptance; reuse is not fresh replay; absent observations are unknown',
        }
    else:
        require(all('work_arithmetic' not in row for row in rows),
                'arithmetic path facts require explicit arithmetic profile')
    if instrumented:
        columns = defaultdict(list)
        for row in rows:
            phases = row.get('submit_phases')
            require(isinstance(phases, list) and [p.get('phase') for p in phases] == list(PHASES),
                    'instrumented observation must retain all seven ordered phase slots')
            for phase in phases:
                columns[phase['phase']].append(phase)
        result['submit_phases'] = []
        for name in PHASES:
            slots = columns[name]
            entered = [p for p in slots if p.get('started') is True]
            result['submit_phases'].append({
                'phase': name, 'slots': len(slots), 'started': len(entered),
                'not_started': len(slots) - len(entered),
                'completed': sum(p.get('completed') is True for p in entered),
                'unfinished': sum(p.get('completed') is not True for p in entered),
                'outcomes': dict(Counter(outcome(p.get('accepted')) for p in entered)),
                'wall_ns': stats([p.get('wall_ns') for p in entered]),
                'thread_cpu_ns': stats([p.get('thread_cpu_ns') for p in entered]),
                'scope': 'entered slots only; unentered slots are counted separately, not zero CPU',
            })
    return result


def completion_work_observation(value):
    """Exact local r13 boundary, never a permanent spent-work or fairness proof."""
    fixed = {
        'schema': 'public-v3-live-owner-completion-work-v1',
        'identity_domain': 'public-v3-complete-work-identity-v1',
        'identity_capacity': 4096, 'identity_storage_bytes': 4096 * 32,
        'epoch_scope': 'same-shared-live-cpu-owner',
        'evicts_live_epoch_identities': False, 'survives_process_restart': False,
        'full_capacity_disables_ordinary_verification': False,
    }
    counters = ('retained_identities', 'live_completions', 'repeated_identity_skips',
                'full_capacity_skips')
    require(type(value) is dict and set(value) == set(fixed) | set(counters),
            'exact r13 completion-work observation required')
    require(all(type(value[key]) is type(expected) and value[key] == expected
                for key, expected in fixed.items()), 'r13 completion-work scope mismatch')
    for key in counters:
        require(type(value[key]) is int and 0 <= value[key] <= 2**64 - 1,
                'r13 completion-work counter must be known')
    require(value['retained_identities'] <= 4096
            and value['live_completions'] <= min(2, value['retained_identities']),
            'r13 completion-work capacity mismatch')
    return dict(value)


def phase_summary(phase):
    mode = phase['mode']
    require(mode in MODES, 'unknown campaign phase')
    base = {'mode': mode, 'state_backend': phase.get('state_backend'),
            'scheduled_confirmation_rounds': ROUNDS,
            'native_phase_criteria_met': phase.get('finite_phase_criteria_met'),
            'startup_or_campaign_error': phase.get('startup_or_campaign_error')}
    policy = None
    if 'public_resource_policy' in phase:
        policy = identify_observation(phase['public_resource_policy'])
        base['public_resource_policy'] = policy
    arithmetic_profile = policy is not None and policy['resource_revision'] == ARITHMETIC_REVISION
    require((phase.get('work_profile') == ARITHMETIC_PROFILE if arithmetic_profile
             else 'work_profile' not in phase and 'work_arithmetic_owner' not in phase),
            'explicit matching arithmetic phase profile required')
    if arithmetic_profile:
        require(phase.get('state_backend') == 'authenticated-v1',
                'arithmetic campaign requires authenticated-v1')
        base['work_profile'] = ARITHMETIC_PROFILE
    if base['startup_or_campaign_error'] is not None:
        base.update(observations_available=False, confirmed_rounds=None)
        return base
    if policy is not None and policy['resource_revision'] in ('r13', ARITHMETIC_REVISION):
        base['completion_work_observation'] = completion_work_observation(
            phase.get('completion_work_observation'))
    else:
        require('completion_work_observation' not in phase,
                'completion-work observation requires explicit r13 policy')
    if arithmetic_profile:
        owner = phase.get('work_arithmetic_owner')
        require(type(owner) is dict and set(owner) == {'schema', 'initial_state', 'slots',
                'retained_software_bytes', 'setup_cpu_ns', 'setup_wall_ns', 'scope',
                'adversarial_key_churn_service_qualified'}
                and owner['schema'] == 'public-v3-campaign-arithmetic-owner-v1'
                and owner['initial_state'] == 'fresh-empty-by-construction'
                and type(owner['slots']) is int and owner['slots'] == 64
                and type(owner['retained_software_bytes']) is int
                and 0 < owner['retained_software_bytes'] <= 4 * 1024 * 1024
                and type(owner['scope']) is str
                and owner['adversarial_key_churn_service_qualified'] is False,
                'fresh bounded arithmetic campaign owner required')
        integer(owner['setup_cpu_ns'])
        integer(owner['setup_wall_ns'])
        base['work_arithmetic_owner'] = owner
    require(phase['duration_seconds'] == 30, 'original 30-second phase required')
    rounds = phase['confirmations']
    indices = [integer(row['round']) for row in rounds]
    require(len(indices) == len(set(indices)) and all(n < ROUNDS for n in indices),
            'unique scheduled confirmation rounds required')
    confirmed = sum(row['confirmed_inside_pressure_window'] is True for row in rounds)
    require(phase['all_signed_rounds_confirmed_in_window'] is (confirmed == ROUNDS),
            'native confirmation aggregate does not match retained rounds')
    submissions, history = phase['submissions'], phase['history']
    attacks = [row for child in phase['children'] for row in
               ((child.get('report') or {}).get('result') or {}).get('calls', [])]
    observer = phase['receiver_observation']
    schema = observer['schema']
    require(schema in ('public-v3-local-request-resource-observation-v1',
                       'public-v3-local-request-resource-observation-v2',
                       'public-v3-local-request-resource-observation-v3'), 'unknown observer schema')
    instrumented = schema.endswith(('-v2', '-v3'))
    if policy is not None:
        require(schema.endswith('-v3') is (policy['resource_revision'] in ('r11', 'r12', 'r13', ARITHMETIC_REVISION)),
                'public policy and observed CPU scope disagree')
    if schema.endswith('-v3'):
        require(observer.get('cpu_includes_reactor_authentication_or_response_signing') is True
                and observer.get('cpu_includes_reactor_authentication') is False
                and observer.get('dispatch_cpu_includes_paid_body_decode') is True
                and observer.get('dispatch_cpu_includes_response_signing') is True,
                'v3 paid body/response CPU scope required')
    require(observer['cpu_intervals_are_nested_not_additive'] is True,
            'nested CPU observation scope required')
    if instrumented:
        require(observer['submit_phase_cpu_excludes_scoped_workers'] is True,
                'dispatcher-only phase CPU scope required')
    roles = defaultdict(set)
    for role, calls in (('honest_submit', submissions), ('client_history', history), ('attack_submit', attacks)):
        for row in calls:
            body = digest(row['public_request_body_digest'])
            # Unknown observations do not share an identity with one another.
            if body is not None:
                roles[body].add(role)
    grouped = defaultdict(list)
    for row in observer['records']:
        if arithmetic_profile and 'work_arithmetic' in row:
            actual = arithmetic_observation(row['work_arithmetic'])
            require(actual['retained_software_bytes'] == owner['retained_software_bytes'],
                    'arithmetic request and phase owner storage disagree')
        body = digest(row.get('body_digest'))
        candidates = roles.get(body, set()) if body is not None else set()
        role = next(iter(candidates)) if len(candidates) == 1 else 'unattributed_or_ambiguous'
        grouped[role].append(row)
    base.update({
        'observations_available': True, 'window_seconds': 30,
        'observed_confirmation_rounds': len(rounds), 'confirmed_rounds': confirmed,
        'unobserved_scheduled_rounds': ROUNDS - len(rounds),
        'confirmation_rounds': [{key: row.get(key) for key in (
            'round', 'started_ns', 'ended_ns', 'confirmed_inside_pressure_window',
            'receiver_hostile_work_rejected_during_round', 'paid_credit_depletion_observed_during_round')}
            for row in rounds],
        'submissions': call_summary(submissions), 'history': call_summary(history),
        'attack_calls': call_summary(attacks),
        'receiver': {'schema': schema, **{key: observer.get(key) for key in (
            'capacity', 'accepted_connections_seen', 'records_not_retained',
            'measurement_failures', 'counter_overflow')},
            'dispatch_cpu_scope': ('paid-body-decode-native-dispatch-signed-response'
                                   if schema.endswith('-v3') else 'native-dispatch-only'),
            'native_observer_complete': phase['observer_complete'],
            'all_retained_records': execution_summary(observer['records'], instrumented, arithmetic_profile),
            'by_observed_body_role': {role: execution_summary(rows, instrumented, arithmetic_profile)
                                      for role, rows in sorted(grouped.items())}},
        'native_service_outcome': phase['service_outcome'],
        'final_cpu_meter': phase['final_meter'], 'final_actual_flow': phase.get('final_actual_flow'),
        'native_verifier_errors': phase['verifier_errors'],
        'receiver_client_state_equal': phase['receiver_client_state_equal'],
        'genuine_budget_depletion_observed': phase['genuine_budget_depletion_observed'],
        'attacker_processes_requested': phase['attacker_processes_requested'],
        'attacker_processes_ready': phase['attacker_processes_ready'],
        'actor_reports_successful_without_cap_or_kill': phase['actor_reports_successful_without_cap_or_kill'],
        'whole_parent_phase_cpu_ns': phase['whole_parent_phase_cpu_ns'],
        'whole_parent_phase_wall_ns': phase['whole_parent_phase_wall_ns'],
        'receiver_and_verifier_setup_cpu_ns': phase['receiver_and_verifier_setup_cpu_ns'],
        'receiver_and_verifier_setup_wall_ns': phase['receiver_and_verifier_setup_wall_ns'],
    })
    return base


def analyze(report):
    arithmetic_profile = report['schema'] == ARITHMETIC_REPORT_SCHEMA
    require(arithmetic_profile or report['schema'] == 'native-public-v3-separate-process-campaign-v2',
            'unknown campaign schema')
    require([row['mode'] for row in report['phases']] == list(MODES), 'all three original phases required')
    require(all(row.get('state_backend') == report.get('state_backend') for row in report['phases']),
            'mixed backend observations')
    if 'public_resource_policy' in report:
        policy = identify_observation(report['public_resource_policy'])
        require(arithmetic_profile is (policy['resource_revision'] == ARITHMETIC_REVISION),
                'campaign schema and arithmetic policy disagree')
        require(all(row.get('public_resource_policy') == report['public_resource_policy']
                    for row in report['phases'] if row.get('startup_or_campaign_error') is None),
                'mixed or missing phase resource policies')
    else:
        require(not arithmetic_profile, 'arithmetic report requires explicit policy')
        require(all('public_resource_policy' not in row for row in report['phases']),
                'phase resource policy without original report identity')
    require((report.get('work_profile') == ARITHMETIC_PROFILE and
             report.get('state_backend') == 'authenticated-v1' and
             report.get('original_r13_campaign_qualified') is False and
             report.get('adversarial_key_churn_service_qualified') is False
             if arithmetic_profile else 'work_profile' not in report),
            'explicit separate arithmetic campaign scope required')
    result = {'schema': 'pon-public-v3-multiprocess-phase-derivation-v2',
            'state_backend': report.get('state_backend'),
            'native_finite_experiment_criteria_met': report['finite_experiment_criteria_met'],
            'native_economics_complete': report['economics_complete'],
            'best_observed_cold_legal_method': report['best_observed_cold_legal_method'],
            'honest_preparation_cpu_ns': report['preparation']['cpu_ns'],
            'honest_preparation_wall_ns': report['preparation']['wall_ns'],
            'phases': [phase_summary(row) for row in report['phases']],
            'scope': {'reader_runs_native_admission': False,
                      'host_or_source_authentication_performed': False,
                      'production_qualification': False, 'business_tps_capacity': None,
                      'fixed_confirmation_denominator_per_phase': ROUNDS,
                      'acknowledgments_are_not_confirmations': True,
                      'cpu_intervals_are_nested_not_additive': True,
                      'submit_phase_cpu_excludes_scoped_workers': True,
                      'cpu_excludes_reactor_authentication': True,
                      'dispatch_cpu_scope_retained_per_observer_schema': True,
                      'submit_phase_cpu_excludes_response_signing': True,
                      'unknown_cpu_is_not_zero': True,
                      'v1_missing_phase_measurements_are_not_reconstructed': True}}
    if arithmetic_profile:
        result.update(source_report_schema=report['schema'], work_profile=ARITHMETIC_PROFILE,
                      public_resource_policy=policy)
        result['scope'].update(original_r13_campaign_qualified=False,
                               adversarial_key_churn_service_qualified=False)
    return result


def analyze_for_retained_schema(report, schema):
    """Reproduce an explicitly named immutable derivation format exactly.

    The original v1 reader accepted only v1/v2 native CPU observations, which
    excluded response construction. Its output had one combined exclusion flag
    and no per-phase dispatch_cpu_scope. These are the only versioned formatting
    differences: every original measurement, outcome, denominator and threshold
    field remains in the exact equality comparison performed by the caller.
    """
    require(schema in ('pon-public-v3-multiprocess-phase-derivation-v1',
                       'pon-public-v3-multiprocess-phase-derivation-v2'),
            'unknown retained phase derivation schema')
    if schema.endswith('-v2'):
        return analyze(report)
    require('public_resource_policy' not in report
            and all('public_resource_policy' not in phase for phase in report['phases']),
            'historical v1 derivation cannot erase explicit public policy')
    require(all(phase.get('startup_or_campaign_error') is not None
                or phase['receiver_observation']['schema'] in (
                    'public-v3-local-request-resource-observation-v1',
                    'public-v3-local-request-resource-observation-v2')
                for phase in report['phases']),
            'historical v1 derivation cannot describe paid-envelope v3 CPU')
    value = analyze(report)
    value['schema'] = schema
    for phase in value['phases']:
        if phase['observations_available']:
            del phase['receiver']['dispatch_cpu_scope']
    scope = value['scope']
    del scope['cpu_excludes_reactor_authentication']
    del scope['dispatch_cpu_scope_retained_per_observer_schema']
    del scope['submit_phase_cpu_excludes_response_signing']
    scope['cpu_excludes_reactor_authentication_and_response_signing'] = True
    return value


def read_report(path, expected, expected_public_policy_id=None):
    require(re.fullmatch('[0-9a-f]{64}', expected), 'explicit report SHA256 required')
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'regular report file required')
    require(path.stat().st_size <= MAX_REPORT_BYTES, 'report exceeds finite reader byte limit')
    raw = path.read_bytes()
    require(len(raw) <= MAX_REPORT_BYTES and hashlib.sha256(raw).hexdigest() == expected,
            'retained report SHA256 mismatch')
    report = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    if expected_public_policy_id is not None:
        digest(expected_public_policy_id)
        require('public_resource_policy' in report,
                'pinned public policy is absent from historical report')
        observed = identify_observation(report['public_resource_policy'])
        require(observed['policy_id'] == expected_public_policy_id,
                'observed public policy does not match requested pin')
    value = analyze(report)
    value['input'] = {'report': str(path), 'bytes': len(raw), 'sha256': expected}
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', required=True, type=Path)
    parser.add_argument('--expected-report-sha256', required=True)
    parser.add_argument('--expected-public-policy-id',
                        help='Require explicit matching policy metadata; never infer it for old reports')
    args = parser.parse_args()
    print(json.dumps(read_report(args.raw_dir / 'report.json', args.expected_report_sha256,
                                args.expected_public_policy_id),
                     sort_keys=True, indent=2, allow_nan=False))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
