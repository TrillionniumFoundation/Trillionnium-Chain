#!/usr/bin/env python3
"""Read retained multiprocess observations; never infer confirmations from ACKs.

Both historical v1 and instrumented v2 receiver observations are accepted.
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

PHASES = ('decode', 'context_owner_wait', 'context', 'work',
          'admission_owner_wait', 'admission', 'submit_result')
MODES = ('baseline', 'from-zero', 'late-product')
ROUNDS = 3
MAX_REPORT_BYTES = 256 * 1024 * 1024


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


def execution_summary(rows, instrumented):
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
    if instrumented:
        columns = defaultdict(list)
        for row in rows:
            phases = row.get('submit_phases')
            require(isinstance(phases, list) and [p.get('phase') for p in phases] == list(PHASES),
                    'v2 observation must retain all seven ordered phase slots')
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


def phase_summary(phase):
    mode = phase['mode']
    require(mode in MODES, 'unknown campaign phase')
    base = {'mode': mode, 'state_backend': phase.get('state_backend'),
            'scheduled_confirmation_rounds': ROUNDS,
            'native_phase_criteria_met': phase.get('finite_phase_criteria_met'),
            'startup_or_campaign_error': phase.get('startup_or_campaign_error')}
    if base['startup_or_campaign_error'] is not None:
        base.update(observations_available=False, confirmed_rounds=None)
        return base
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
                       'public-v3-local-request-resource-observation-v2'), 'unknown observer schema')
    instrumented = schema.endswith('-v2')
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
            'native_observer_complete': phase['observer_complete'],
            'all_retained_records': execution_summary(observer['records'], instrumented),
            'by_observed_body_role': {role: execution_summary(rows, instrumented)
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
    require(report['schema'] == 'native-public-v3-separate-process-campaign-v2', 'unknown campaign schema')
    require([row['mode'] for row in report['phases']] == list(MODES), 'all three original phases required')
    require(all(row.get('state_backend') == report.get('state_backend') for row in report['phases']),
            'mixed backend observations')
    return {'schema': 'pon-public-v3-multiprocess-phase-derivation-v1',
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
                      'cpu_excludes_reactor_authentication_and_response_signing': True,
                      'unknown_cpu_is_not_zero': True,
                      'v1_missing_phase_measurements_are_not_reconstructed': True}}


def read_report(path, expected):
    require(re.fullmatch('[0-9a-f]{64}', expected), 'explicit report SHA256 required')
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'regular report file required')
    require(path.stat().st_size <= MAX_REPORT_BYTES, 'report exceeds finite reader byte limit')
    raw = path.read_bytes()
    require(len(raw) <= MAX_REPORT_BYTES and hashlib.sha256(raw).hexdigest() == expected,
            'retained report SHA256 mismatch')
    value = analyze(json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON'))))
    value['input'] = {'report': str(path), 'bytes': len(raw), 'sha256': expected}
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', required=True, type=Path)
    parser.add_argument('--expected-report-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(read_report(args.raw_dir / 'report.json', args.expected_report_sha256),
                     sort_keys=True, indent=2, allow_nan=False))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
