#!/usr/bin/env python3
"""Read original campaign bytes only. No native execution or attack simulation."""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import sys
import zipfile

SOURCE = '131f673d9563e72aca7139f3239856957d118d49'
ARCHIVE_SHA = '2882b94bb4edc617ecee45b65fe4e3ad9607a8330505e1ccc38ec13933e680f5'
REPORT_SHA = {
    1: '925320d9600607b74fc33886dc8f09ba40d19d42ea9d854891f71a83aef1133f',
    2: '1b671f8ff9e604c6969bcd663215f382e1659042ffcea865272ab45aaa652445',
    3: '7122a8c740ab710ff84b2d35fb455239859d544514bedec7bc2bffca0f757b14',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key: '+key)
        result[key] = value
    return result


def number(value, label, minimum=0):
    require(type(value) is int and (minimum is None or value >= minimum), label)
    return value


def sum_known(rows, key):
    values = [row[key] for row in rows if row[key] is not None]
    for value in values:
        number(value, key)
    return {'known_sum_ns': sum(values), 'known_count': len(values),
            'unknown_count': len(rows)-len(values)}


def exact_flow(flow, burst, reserve):
    require(isinstance(flow, dict) and flow['balance_identity_verified'] is True,
            'missing or invalid actual flow')
    require(flow['initial_credit_ns'] == burst, 'changed initial credit')
    for key in ('credited_refill_ns', 'paid_cpu_debit_ns', 'settlement_discard_ns',
                'discarded_refill_ns', 'live_debited_cpu_ns', 'settlement_residual_cpu_ns',
                'booked_reservation_ns', 'live_owners', 'unsettled_known_live_cpu_ns',
                'settled_full_cpu_ns'):
        number(flow[key], key)
    paid = number(flow['remaining_paid_credit_ns'], 'paid balance', None)
    stored = number(flow['stored_credit_ns'], 'stored balance', None)
    termination = number(flow.get('termination_reserved_ns', 0), 'termination reserve')
    require(paid == burst+flow['credited_refill_ns']-flow['paid_cpu_debit_ns']-
            flow['settlement_discard_ns'], 'paid identity')
    require(flow['paid_cpu_debit_ns'] == flow['live_debited_cpu_ns']+
            flow['settlement_residual_cpu_ns'], 'CPU debit identity')
    require(stored == paid-flow['booked_reservation_ns']-termination, 'reservation identity')
    require(flow['booked_reservation_ns'] == reserve*flow['live_owners'], 'owner reserve')
    return flow


def interval_bounds(phase):
    """Bounds the already-debited scalar ledger, not unsampled physical CPU."""
    initial = phase['initial_meter']
    burst, reserve = initial['burst_ns'], initial['start_reserve_ns']
    require((burst, reserve, initial['refill_ns_per_second'], initial['worker_limit']) ==
            (2_000_000_000, 100_000_000, 250_000_000, 2), 'original geometry')
    require(initial['stored_credit_ns'] == burst and initial['in_flight'] == 0 and
            initial['accounting_unavailable'] is False, 'constructor anchor')
    final_meter = phase['final_meter']
    require(final_meter['accounting_unavailable'] is False and final_meter['in_flight'] == 0,
            'final accounting unavailable or live')
    metrics = phase['service_outcome']['Ok']
    require(metrics['mutation_cpu_clock_failures'] == 0 and
            metrics['mutation_cpu_unavailable_after_shutdown'] is False, 'unknown CPU')
    # Source new() and initial_meter jointly establish the fresh original epoch.
    flows = [{'credited_refill_ns': 0, 'paid_cpu_debit_ns': 0,
              'settlement_discard_ns': 0, 'remaining_paid_credit_ns': burst}]
    tags = [{'kind': 'constructor_and_initial_meter', 'sample_index': None,
             'time_bracket_ns': None}]
    previous_end = -1
    require(phase['budget_samples'], 'no samples')
    for index, row in enumerate(phase['budget_samples']):
        observed = row['meter']['Ok']
        require(observed['clock_failures'] == 0 and
                observed['meter']['accounting_unavailable'] is False, 'unknown sample CPU')
        start = number(row['observation_started_ns'], 'sample start')
        end = number(row['observation_ended_ns'], 'sample end')
        require(previous_end <= start <= end, 'sample order')
        previous_end = end
        flows.append(exact_flow(observed['actual_flow'], burst, reserve))
        tags.append({'kind': 'original_sample', 'sample_index': index,
                     'time_bracket_ns': [start, end]})
    final = exact_flow(phase['final_actual_flow'], burst, reserve)
    require(final['live_owners'] == 0 and final['booked_reservation_ns'] == 0 and
            final.get('termination_reserved_ns', 0) == 0 and
            final['unsettled_known_live_cpu_ns'] == 0, 'unsettled final CPU')
    require(final['paid_cpu_debit_ns'] == final['settled_full_cpu_ns'] ==
            metrics['mutation_cpu_charged_ns'], 'final paid/settled/metric mismatch')
    require(final['stored_credit_ns'] == final_meter['stored_credit_ns'], 'final meter mismatch')
    flows.append(final)
    tags.append({'kind': 'final_actual_flow_after_service_finish', 'sample_index': None,
                 'time_bracket_ns': None})
    pairs = []
    for index, (before, after) in enumerate(zip(flows, flows[1:])):
        delta = {key: after[key]-before[key] for key in
                 ('credited_refill_ns', 'paid_cpu_debit_ns', 'settlement_discard_ns')}
        require(min(delta.values()) >= 0, 'nonmonotone cumulative flow')
        lower = (before['remaining_paid_credit_ns']-delta['paid_cpu_debit_ns']-
                 delta['settlement_discard_ns'])
        pairs.append({'pair_index': index, 'from': tags[index], 'to': tags[index+1],
                      'paid_balance_from_ns': before['remaining_paid_credit_ns'],
                      'delta': delta, 'lower_bound_ns': lower})
    worst = min(pairs, key=lambda row: row['lower_bound_ns'])
    return {'status': 'KNOWN_FOR_ORIGINAL_LEDGER_TRAJECTORY',
            'formula': 'P(t) >= P_i - (D_j-D_i) - (S_j-S_i), since credited F is nondecreasing',
            'scope': 'already debited scalar paid balance; not unsampled physical CPU; not all payloads',
            'sample_count': len(phase['budget_samples']), 'pair_count': len(pairs),
            'lower_bound_ns': worst['lower_bound_ns'], 'start_threshold_ns': reserve,
            'all_ledger_intervals_above_threshold': worst['lower_bound_ns'] >= reserve,
            'maximum_between_snapshot_debit_ns': max(r['delta']['paid_cpu_debit_ns'] for r in pairs),
            'worst_pair': worst, 'prefix': pairs[0], 'tail': pairs[-1]}, pairs


def stage_matrix(rows):
    result = {}
    for name in ('decode', 'context_owner_wait', 'context', 'work',
                 'admission_owner_wait', 'admission', 'submit_result'):
        selected = [item for row in rows for item in row['submit_phases'] if item['phase'] == name]
        require(len(selected) == len(rows), 'missing/duplicate Submit phase')
        result[name] = {'started': sum(r['started'] for r in selected),
                        'completed': sum(r['completed'] for r in selected),
                        'accepted': sum(r['accepted'] is True for r in selected),
                        'rejected': sum(r['accepted'] is False for r in selected),
                        'thread_cpu': sum_known([r for r in selected if r['started']], 'thread_cpu_ns'),
                        'wall': sum_known([r for r in selected if r['started']], 'wall_ns')}
    return result


def network_on_time(row):
    return row['status'] == 'ok' and row['returned_after_window'] is False


def phase_matrix(run, phase_index, phase):
    mode = phase['mode']
    actors = [row['report']['result'] for row in phase['children']]
    require(len(actors) == (0 if mode == 'baseline' else 24), 'original actor denominator')
    require(phase['duration_seconds'] == 30, 'original window')
    digests = {row['acquisition']['public_request_body_digest'] for row in actors}
    require(len(digests) == len(actors), 'distinct acquired bodies')
    calls = [call for actor in actors for call in actor['calls']]
    require(all(c['public_request_body_digest'] == actor['acquisition']['public_request_body_digest']
                for actor in actors for c in actor['calls']), 'changed actor body')
    captured = phase['receiver_observation']
    records = captured['records']
    rows = [r for r in records if r['body_digest'] is not None and
            bytes(r['body_digest']).hex() in digests]
    require(all(r['observation_failed'] is False and r['complete'] is True for r in records),
            'incomplete receiver observation')
    stage = stage_matrix(rows)
    path_counts = Counter()
    for row in rows:
        if row['full_work_started']:
            path = 'W1_rejected_response_complete' if row['response_frame_complete'] else 'W1_rejected_no_complete_response'
            require(row['full_work_accepted'] is False, 'unexpected accepted hostile W1')
        elif row['dispatch_started']:
            path = 'paid_worker_dispatch_before_W1'
        elif row['task_created']:
            path = 'task_before_dispatch_'+str(row['terminal_phase'])
        else:
            path = 'connection_before_task_'+str(row['terminal_phase'])
        path_counts[path] += 1
    require(stage['admission']['started'] == 0, 'unexpected original hostile admission')
    imports = [row['client_import'] for row in phase['history'] if 'client_import' in row]
    pages = [row['response']['value'] for row in phase['history'] if network_on_time(row)]
    metrics = phase['service_outcome']['Ok']
    flow = phase['final_actual_flow']
    expected_errors = Counter(call['response']['value']['error'] for call in calls if call['status'] == 'refused')
    acquisitions = [{key: actor['acquisition'][key] for key in
                     ('packet_bytes', 'public_request_body_digest', 'packet_digest', 'proof_digest',
                      'setup_calls', 'acquisition_cpu_ns', 'acquisition_wall_ns',
                      'diagnostic_result', 'diagnostic_cpu_ns', 'diagnostic_wall_ns')}
                    | {'worker': actor['worker'], 'attempts': len(actor['acquisition']['attempts']),
                       'calls': len(actor['calls'])} for actor in actors]
    for row in acquisitions:
        require(row['diagnostic_result'] == {'Err': 'Transcript' if mode == 'from-zero' else 'Product'},
                'original acquisition relation mismatch')
    return {
        'run': run, 'mode': mode, 'raw_member': f'run-{run}-raw/report.json',
        'raw_phase_pointer': f'/phases/{phase_index}', 'acquisitions': acquisitions,
        'attack_calls': len(calls), 'attack_statuses': dict(Counter(c['status'] for c in calls)),
        'signed_rejection_errors': dict(expected_errors),
        'client_errors': dict(Counter(c['error'] for c in calls if c['status'] == 'error')),
        'calls_after_window': sum(c['returned_after_window'] for c in calls),
        'receiver_digest_matches': len(rows), 'client_minus_receiver_records': len(calls)-len(rows),
        'receiver_path_counts': dict(path_counts), 'receiver_stage_matrix': stage,
        'receiver_full_work_cpu': sum_known([r for r in rows if r['full_work_started']], 'full_work_thread_cpu_ns'),
        'receiver_dispatch_cpu': sum_known([r for r in rows if r['dispatch_started']], 'dispatch_thread_cpu_ns'),
        'receiver_response_frames_complete': sum(r['response_frame_complete'] for r in rows),
        'receiver_observer_metadata': {key: value for key, value in captured.items() if key != 'records'},
        'honest': {'planned_rounds': 3, 'observed_rounds': len(phase['confirmations']),
                   'confirmed_rounds': sum(r['confirmed_inside_pressure_window'] for r in phase['confirmations']),
                   'unobserved_rounds': 3-len(phase['confirmations']), 'planned_business_packets': 21,
                   'submitted_packets': len(phase['submissions']),
                   'on_time_signed_submissions': sum(network_on_time(r) for r in phase['submissions']),
                   'history_attempts': len(phase['history']),
                   'on_time_history_responses': sum(network_on_time(r) for r in phase['history']),
                   'history_import_attempts': len(imports),
                   'history_import_successes': sum(r['succeeded'] for r in imports),
                   'history_import_failures': sum(not r['succeeded'] for r in imports),
                   'actual_confirmation_calls': sum('client_confirmation' in r for r in phase['history']),
                   'history_page_sizes': [len(r['packets']) for r in pages],
                   'history_page_complete_flags': [r['complete'] for r in pages],
                   'verifier_errors': phase['verifier_errors'], 'client_imports': imports},
        'final_actual_flow': flow,
        'service_cpu_metrics': {key: value for key, value in metrics.items() if 'cpu' in key},
        'whole_parent_cpu_ns': phase['whole_parent_phase_cpu_ns'],
        'whole_parent_wall_ns': phase['whole_parent_phase_wall_ns'],
        'setup_cpu_ns': phase['receiver_and_verifier_setup_cpu_ns'],
        'setup_wall_ns': phase['receiver_and_verifier_setup_wall_ns'],
        'completion_work_observation': phase['completion_work_observation'],
        'actors_exit_success': sum(r['exit_success'] for r in phase['children']),
        'actors_forced_kill': sum(r['parent_forced_kill'] for r in phase['children']),
        'actors_attempt_cap': sum(r['attempt_cap_reached'] for r in actors),
        'original_phase_criteria': phase['finite_phase_criteria_met'],
        'original_depletion_verdict': phase['genuine_budget_depletion_observed'],
        'cost_scope': 'nested thread intervals are not added; receiver paid total includes honest requests; separate History account and reactor are outside it',
    }


def analyze(archive):
    raw_sha = hashlib.sha256()
    with archive.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            raw_sha.update(chunk)
    require(archive.stat().st_size == 50_535_162 and raw_sha.hexdigest() == ARCHIVE_SHA,
            'wrong original archive bytes')
    reports, matrix, bounds, intervals = [], [], [], []
    with zipfile.ZipFile(archive) as zipped:
        require(len(zipped.namelist()) == len(set(zipped.namelist())), 'duplicate archive member')
        for run in range(1, 4):
            member = f'run-{run}-raw/report.json'
            require(zipped.getinfo(member).file_size <= 20_000_000, 'report size')
            raw = zipped.read(member)
            require(hashlib.sha256(raw).hexdigest() == REPORT_SHA[run], 'wrong raw report')
            report = json.loads(raw, object_pairs_hook=unique)
            require([r['mode'] for r in report['phases']] == ['baseline', 'from-zero', 'late-product'],
                    'original phase matrix')
            require(report['preparation']['actual_signed_seed_transfers'] == 1024 and
                    report['preparation']['business_blocks'] == 21, 'original input set')
            reports.append({'member': member, 'bytes': len(raw), 'sha256': REPORT_SHA[run]})
            for index, phase in enumerate(report['phases']):
                matrix.append(phase_matrix(run, index, phase))
                bound, pairs = interval_bounds(phase)
                identity = {'run': run, 'mode': phase['mode'], 'raw_member': member,
                            'raw_phase_pointer': f'/phases/{index}', 'raw_sha256': REPORT_SHA[run]}
                bounds.append(identity | bound)
                intervals.extend(identity | pair for pair in pairs)
    return {
        'schema': 'original-r14-body-matched-attack-matrix-r8-v1',
        'scope': 'new read-only computation from original recorded measurements; no native run, crypto, simulation or qualification',
        'source_commit': SOURCE, 'archive_bytes': archive.stat().st_size,
        'archive_sha256': ARCHIVE_SHA, 'reports': reports, 'phases': matrix,
        'continuous_ledger_bounds': bounds,
        'all_original_failures_preserved': True, 'resource_profile_changed': False,
        'work_package_2b_closed': False, 'public_network_ready': False,
    }, intervals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    try:
        report, intervals = analyze(args.archive)
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile) as error:
        failure = {'status': 'UNKNOWN', 'diagnostic_complete': False,
                   'error': str(error), 'work_package_2b_closed': False}
        (args.out/'failure.json').write_text(json.dumps(failure, indent=2)+'\n')
        print(json.dumps(failure), file=sys.stderr)
        return 1
    (args.out/'matrix.json').write_text(json.dumps(report, indent=2)+'\n')
    raw = ''.join(json.dumps(row, sort_keys=True)+'\n' for row in intervals).encode()
    (args.out/'flow-intervals.jsonl.gz').write_bytes(gzip.compress(raw, mtime=0))
    print(json.dumps({'status': 'READBACK_COMPLETE', 'phases': len(report['phases']),
                      'flow_intervals': len(intervals), 'work_package_2b_closed': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
